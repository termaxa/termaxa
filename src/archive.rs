//! What an archive holds, read from its own index and never unpacked (#12):
//! the names a `tar -x`, an `unzip` or an `Expand-Archive` would write.
//!
//! A zip keeps a central directory at its end, and a tar a header before
//! each member; both are read as they are stored, without decompressing a
//! byte. A compressed tar is not read: the gate carries no decompressor, and
//! it says which compression it met rather than guess at the names inside.
//! The reading has the delete preview's budget, counted in entries and in
//! time, and says when it stopped.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::{Duration, Instant};

/// How many entries one reading takes before it stops, and for how long it
/// reads: the delete preview's 5,000 files are a count of what is copied,
/// and a name costs far less to read than a file does to copy.
const MOST_ENTRIES: usize = 20_000;
const MOST_TIME: Duration = Duration::from_millis(300);

/// What an archive was found to hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listing {
    /// The names of the members that unpack as files, links or devices,
    /// as the archive stores them (`/` between components; a directory's
    /// own entry is left out). `capped` when the reading stopped at its
    /// budget, and there are names it did not reach.
    Names { names: Vec<String>, capped: bool },
    /// Not read, and why, in words a preview can say: "gzip-compressed",
    /// "in a format the gate does not read".
    Unread(&'static str),
}

/// What `path` holds. `zip_first` for `unzip` and `Expand-Archive`, which
/// read only zips and find one by its end (a self-extracting zip starts with
/// a program); `tar` is told the format by the first bytes.
pub fn list(path: &Path, zip_first: bool) -> Listing {
    let Ok(meta) = std::fs::metadata(path) else {
        return Listing::Unread("not there to read");
    };
    if !meta.is_file() {
        return Listing::Unread("not a file the gate can open");
    }
    // The preview, the copy aside and each of the path rules' readings ask
    // of the same archive in one run of the gate: it is read once, and
    // read again only when it has changed.
    type Seen = (
        std::path::PathBuf,
        bool,
        u64,
        Option<std::time::SystemTime>,
        Listing,
    );
    static SEEN: std::sync::OnceLock<std::sync::Mutex<Vec<Seen>>> = std::sync::OnceLock::new();
    let key = (
        path.to_path_buf(),
        zip_first,
        meta.len(),
        meta.modified().ok(),
    );
    let seen = SEEN.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    if let Ok(seen) = seen.lock() {
        if let Some((.., listing)) = seen
            .iter()
            .find(|(p, z, len, at, _)| (p, *z, *len, *at) == (&key.0, key.1, key.2, key.3))
        {
            return listing.clone();
        }
    }
    let listing = read_listing(path, zip_first, &meta);
    if let Ok(mut seen) = seen.lock() {
        if seen.len() >= 8 {
            seen.remove(0);
        }
        seen.push((key.0, key.1, key.2, key.3, listing.clone()));
    }
    listing
}

fn read_listing(path: &Path, zip_first: bool, meta: &std::fs::Metadata) -> Listing {
    let Ok(mut file) = File::open(path) else {
        return Listing::Unread("not a file the gate can open");
    };
    let mut head = [0u8; 512];
    let got = read_up_to(&mut file, &mut head);
    let head = &head[..got];
    let started = Instant::now();
    if zip_first || head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        if let Some((names, capped)) = zip_names(&mut file, meta.len(), started) {
            return Listing::Names { names, capped };
        }
        if zip_first {
            return Listing::Unread("not a zip the gate can read");
        }
    }
    if let Some(kind) = compression(head) {
        return Listing::Unread(kind);
    }
    if file.seek(SeekFrom::Start(0)).is_ok() {
        if let Some((names, capped)) = tar_names(&mut file, started) {
            return Listing::Names { names, capped };
        }
    }
    Listing::Unread("in a format the gate does not read")
}

/// The compression a file starts with, by its magic number.
fn compression(head: &[u8]) -> Option<&'static str> {
    const KINDS: &[(&[u8], &str)] = &[
        (b"\x1f\x8b", "gzip-compressed"),
        (b"BZh", "bzip2-compressed"),
        (b"\xfd7zXZ\x00", "xz-compressed"),
        (b"\x28\xb5\x2f\xfd", "zstd-compressed"),
        (b"LZIP", "lzip-compressed"),
        (b"\x04\x22\x4d\x18", "lz4-compressed"),
        (b"\x1f\x9d", "compress-compressed"),
        (b"\x89LZO", "lzop-compressed"),
    ];
    KINDS
        .iter()
        .find(|(magic, _)| head.starts_with(magic))
        .map(|(_, kind)| *kind)
}

fn read_up_to(file: &mut File, buf: &mut [u8]) -> usize {
    let mut got = 0;
    while got < buf.len() {
        match file.read(&mut buf[got..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    got
}

fn spent(started: Instant, entries: usize) -> bool {
    entries >= MOST_ENTRIES || started.elapsed() > MOST_TIME
}

fn u16_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?) as u64)
}

fn u32_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?) as u64)
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// A zip's member names, from its central directory: found through the end
/// of central directory record in the file's last 64 KiB (and its zip64
/// form for an archive past 4 GiB or 65,535 entries), then read entry by
/// entry. A name ending in `/` is a directory's own entry.
fn zip_names(file: &mut File, len: u64, started: Instant) -> Option<(Vec<String>, bool)> {
    let tail_len = len.min(65_557);
    file.seek(SeekFrom::Start(len - tail_len)).ok()?;
    let mut tail = vec![0u8; tail_len as usize];
    file.read_exact(&mut tail).ok()?;
    let eocd = (0..tail.len().saturating_sub(21))
        .rev()
        .find(|&i| tail[i..].starts_with(b"PK\x05\x06"))?;
    let mut entries = u16_at(&tail, eocd + 10)?;
    let mut offset = u32_at(&tail, eocd + 16)?;
    if entries == 0xFFFF || offset == 0xFFFF_FFFF {
        // The zip64 locator stands just before the record.
        let locator = eocd.checked_sub(20)?;
        if !tail[locator..].starts_with(b"PK\x06\x07") {
            return None;
        }
        let at = u64_at(&tail, locator + 8)?;
        file.seek(SeekFrom::Start(at)).ok()?;
        let mut record = [0u8; 56];
        file.read_exact(&mut record).ok()?;
        if !record.starts_with(b"PK\x06\x06") {
            return None;
        }
        entries = u64_at(&record, 32)?;
        offset = u64_at(&record, 48)?;
    }
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut reader = BufReader::new(file);
    let mut names = Vec::new();
    let mut fixed = [0u8; 46];
    for read in 0..entries {
        if spent(started, read as usize) {
            return Some((names, true));
        }
        reader.read_exact(&mut fixed).ok()?;
        if !fixed.starts_with(b"PK\x01\x02") {
            return None;
        }
        let name_len = u16_at(&fixed, 28)? as usize;
        let rest = u16_at(&fixed, 30)? + u16_at(&fixed, 32)?;
        let mut name = vec![0u8; name_len];
        reader.read_exact(&mut name).ok()?;
        reader.seek_relative(rest as i64).ok()?;
        let name = String::from_utf8_lossy(&name).to_string();
        if !name.is_empty() && !name.ends_with('/') {
            names.push(name);
        }
    }
    Some((names, false))
}

/// A number in a tar header: octal digits, or the base-256 form GNU tar
/// writes for a size past 8 GiB (the field's first byte with its top bit
/// set).
fn tar_number(field: &[u8]) -> Option<u64> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        let mut n: u64 = (field[0] & 0x7f) as u64;
        for b in &field[1..] {
            n = n.checked_mul(256)?.checked_add(*b as u64)?;
        }
        return Some(n);
    }
    let text: String = field
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| *b as char)
        .collect();
    let text = text.trim();
    if text.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(text, 8).ok()
}

fn tar_text(field: &[u8]) -> String {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).to_string()
}

/// A tar's member names, header by header: POSIX ustar's prefix and name,
/// GNU tar's long names (`L`) and pax's `path=` records (`x`), each data
/// area stepped over. Directories (`5`), volume labels and the metadata
/// entries themselves are not members that unpack as files. A header whose
/// checksum does not hold ends the reading; at the first one it means the
/// file is not a tar.
fn tar_names(file: &mut File, started: Instant) -> Option<(Vec<String>, bool)> {
    let mut reader = BufReader::new(file);
    let mut names = Vec::new();
    let mut header = [0u8; 512];
    let mut next_name: Option<String> = None;
    let mut first = true;
    loop {
        if spent(started, names.len()) {
            return Some((names, true));
        }
        if reader.read_exact(&mut header).is_err() {
            if first {
                return None;
            }
            break;
        }
        if header.iter().all(|b| *b == 0) {
            break;
        }
        let stored = tar_number(&header[148..156])?;
        let sum: u64 = header
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    *b as u64
                }
            })
            .sum();
        if sum != stored {
            if first {
                return None;
            }
            break;
        }
        first = false;
        let size = tar_number(&header[124..136])?;
        let padded = size.div_ceil(512) * 512;
        let kind = header[156];
        match kind {
            b'L' | b'x' => {
                // The next member's name, in this entry's data.
                let mut data = vec![0u8; usize::try_from(size.min(1 << 20)).ok()?];
                reader.read_exact(&mut data).ok()?;
                reader
                    .seek_relative((padded - data.len() as u64) as i64)
                    .ok()?;
                next_name = if kind == b'L' {
                    Some(tar_text(&data))
                } else {
                    pax_path(&data).or(next_name)
                };
                continue;
            }
            b'K' | b'g' | b'V' | b'5' | b'D' => {
                reader.seek_relative(padded as i64).ok()?;
                if kind == b'5' || kind == b'D' {
                    next_name = None;
                }
                continue;
            }
            _ => {}
        }
        let name = next_name.take().unwrap_or_else(|| {
            let name = tar_text(&header[0..100]);
            let prefix = tar_text(&header[345..500]);
            if &header[257..263] == b"ustar\0" && !prefix.is_empty() {
                format!("{prefix}/{name}")
            } else {
                name
            }
        });
        if !name.is_empty() && !name.ends_with('/') {
            names.push(name);
        }
        reader.seek_relative(padded as i64).ok()?;
    }
    Some((names, false))
}

/// The `path=` of a pax extended header: records of `length key=value\n`.
fn pax_path(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    text.lines().find_map(|record| {
        let (_, kv) = record.split_once(' ')?;
        kv.strip_prefix("path=").map(str::to_string)
    })
}

#[cfg(test)]
pub mod testing {
    //! Archives made in a test, byte by byte: a POSIX ustar and a stored
    //! (uncompressed) zip, each a valid archive the real tools unpack.

    /// A ustar archive of `entries`: a name ending in `/` is a directory.
    pub fn tar_of(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in entries {
            let mut h = [0u8; 512];
            // A name past 100 bytes is split at a `/` into ustar's prefix
            // and name fields.
            let (prefix, base) = match name
                .match_indices('/')
                .map(|(i, _)| i)
                .find(|&i| name.len() > 100 && name.len() - i - 1 <= 100)
            {
                Some(i) => (&name[..i], &name[i + 1..]),
                None => ("", *name),
            };
            h[..base.len()].copy_from_slice(base.as_bytes());
            h[100..108].copy_from_slice(b"0000644\0");
            h[108..116].copy_from_slice(b"0000000\0");
            h[116..124].copy_from_slice(b"0000000\0");
            let size = if name.ends_with('/') { 0 } else { data.len() };
            h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
            h[136..148].copy_from_slice(b"00000000000\0");
            h[156] = if name.ends_with('/') { b'5' } else { b'0' };
            h[257..263].copy_from_slice(b"ustar\0");
            h[263..265].copy_from_slice(b"00");
            h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
            h[148..156].copy_from_slice(b"        ");
            let sum: u32 = h.iter().map(|b| *b as u32).sum();
            h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
            out.extend_from_slice(&h);
            if size > 0 {
                out.extend_from_slice(data.as_bytes());
                out.resize(out.len().div_ceil(512) * 512, 0);
            }
        }
        out.resize(out.len() + 1024, 0);
        out
    }

    /// A zip of `entries`, stored without compression.
    pub fn zip_of(entries: &[(&str, &str)]) -> Vec<u8> {
        let crc = |data: &[u8]| -> u32 {
            let mut c = 0xFFFF_FFFFu32;
            for b in data {
                c ^= *b as u32;
                for _ in 0..8 {
                    c = if c & 1 != 0 {
                        (c >> 1) ^ 0xEDB8_8320
                    } else {
                        c >> 1
                    };
                }
            }
            !c
        };
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data) in entries {
            let offset = out.len() as u32;
            let (sum, len) = (crc(data.as_bytes()), data.len() as u32);
            let mut local = Vec::new();
            local.extend_from_slice(b"PK\x03\x04");
            local.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            local.extend_from_slice(&sum.to_le_bytes());
            local.extend_from_slice(&len.to_le_bytes());
            local.extend_from_slice(&len.to_le_bytes());
            local.extend_from_slice(&(name.len() as u16).to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(name.as_bytes());
            local.extend_from_slice(data.as_bytes());
            out.extend_from_slice(&local);
            central.extend_from_slice(b"PK\x01\x02");
            central.extend_from_slice(&[20, 3, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            central.extend_from_slice(&sum.to_le_bytes());
            central.extend_from_slice(&len.to_le_bytes());
            central.extend_from_slice(&len.to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let at = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&at.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{tar_of, zip_of};
    use super::*;
    use crate::testutil::TempTree;

    fn names(l: Listing) -> Vec<String> {
        match l {
            Listing::Names { names, capped } => {
                assert!(!capped);
                names
            }
            other => panic!("not read: {other:?}"),
        }
    }

    /// A zip's names come from its central directory and a tar's from its
    /// headers, a long ustar name with its prefix; a directory's own entry
    /// is not a member that unpacks as a file.
    #[test]
    fn a_zip_and_a_tar_are_read_for_their_member_names() {
        let tmp = TempTree::new("archive-names");
        let long = format!("deep/{}/file.txt", "d".repeat(120));
        let entries = [
            ("app.py", "new"),
            ("pkg/", ""),
            ("pkg/__init__.py", "x"),
            (long.as_str(), "y"),
        ];
        std::fs::write(tmp.path().join("a.zip"), zip_of(&entries)).unwrap();
        std::fs::write(tmp.path().join("a.tar"), tar_of(&entries)).unwrap();
        let want = vec!["app.py".to_string(), "pkg/__init__.py".to_string(), long];
        assert_eq!(names(list(&tmp.path().join("a.zip"), true)), want);
        assert_eq!(names(list(&tmp.path().join("a.zip"), false)), want);
        assert_eq!(names(list(&tmp.path().join("a.tar"), false)), want);
    }

    /// A compressed tar is not read, and the reading says which compression
    /// it met; nor is anything that is no archive, or not there.
    #[test]
    fn a_compressed_or_unknown_file_is_not_read_and_says_why() {
        let tmp = TempTree::new("archive-unread");
        std::fs::write(tmp.path().join("a.tgz"), b"\x1f\x8b\x08\0rest").unwrap();
        std::fs::write(tmp.path().join("a.txz"), b"\xfd7zXZ\0rest").unwrap();
        std::fs::write(tmp.path().join("notes.txt"), "just text").unwrap();
        assert_eq!(
            list(&tmp.path().join("a.tgz"), false),
            Listing::Unread("gzip-compressed")
        );
        assert_eq!(
            list(&tmp.path().join("a.txz"), false),
            Listing::Unread("xz-compressed")
        );
        assert_eq!(
            list(&tmp.path().join("notes.txt"), false),
            Listing::Unread("in a format the gate does not read")
        );
        assert_eq!(
            list(&tmp.path().join("notes.txt"), true),
            Listing::Unread("not a zip the gate can read")
        );
        assert_eq!(
            list(&tmp.path().join("gone.tar"), false),
            Listing::Unread("not there to read")
        );
    }
}
