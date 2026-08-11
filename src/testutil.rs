//! Test-only isolation for the process-global state this suite reaches into.
//!
//! `TERMAXA_HOME` and the working directory belong to the PROCESS, and cargo
//! runs tests as threads inside one process. Three tests in `paths.rs` used to
//! set them by hand and delete the trees they pointed at, which produced a
//! flake that read as a missing policy (#17) and, on every green run in
//! between, quietly wrote state into the developer's real `~/.termaxa`.
//!
//! Both halves of that came from the same thing: setting up a test correctly
//! took knowledge the test itself did not carry. So the safe path is the only
//! path here.
//!
//! Two guards, because the costs differ:
//!
//! - [`TempTree`] is a scratch directory that removes itself. It touches
//!   nothing process-global, takes no lock, and tests using only it still run
//!   in parallel. Most tests want this one.
//! - [`TestEnv`] is a `TempTree` plus the lock, `TERMAXA_HOME` pointed into
//!   the tree, and the cwd restored on the way out. Only tests that need the
//!   environment redirected should pay for the serialisation.
//!
//! ```ignore
//! let tmp = TempTree::new("my-case");
//! let log = tmp.file("audit.jsonl", "{}\n");
//!
//! let env = TestEnv::new("my-case");     // when TERMAXA_HOME matters
//! let proj = env.project("proj");        // <root>/proj/.termaxa/policy.yaml
//! ```
//!
//! Both fail the test that leaves something behind: every guard asserts its
//! own tree is gone, and `TestEnv` additionally watches the real `~/.termaxa`.
//! A helper nobody is obliged to use stops being used, so
//! `no_module_builds_a_temp_path_by_hand` reads the source and fails on a
//! `temp_dir()` call outside this module. That is what keeps this the only
//! obvious way rather than merely an available one.
//!
//! One `TestEnv` per test. `std::sync::Mutex` is not reentrant, so a second
//! `TestEnv::new` while one is alive deadlocks rather than failing. `TempTree`
//! takes no lock and nests freely.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

static GLOBAL_ENV: Mutex<()> = Mutex::new(());
static SEQ: AtomicUsize = AtomicUsize::new(0);

/// Take the lock, tolerating poisoning: if a test panicked while holding it,
/// the rest should report their own verdicts instead of failing as collateral
/// and hiding which one actually broke.
fn lock() -> MutexGuard<'static, ()> {
    GLOBAL_ENV.lock().unwrap_or_else(|e| e.into_inner())
}

/// Claim a fresh tree. The pid keeps two concurrent `cargo test` runs apart
/// and the counter keeps two guards sharing a label apart.
fn claim(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "tmx-{}-{}-{}",
        label,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("test root must be creatable");
    root
}

/// Remove a tree, reporting whether it is actually gone.
///
/// A cleanup that silently failed is how litter accumulates in the first
/// place, so the guard says so rather than shrugging.
fn release(root: &Path) -> bool {
    let _ = std::fs::remove_dir_all(root);
    !root.exists()
}

/// A scratch directory that removes itself, with no lock and no environment
/// changes. The default way to get a path to write to in a test.
pub struct TempTree {
    root: PathBuf,
}

impl TempTree {
    pub fn new(label: &str) -> Self {
        Self { root: claim(label) }
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    /// A subdirectory, created.
    pub fn dir(&self, name: &str) -> PathBuf {
        let dir = self.root.join(name);
        std::fs::create_dir_all(&dir).expect("scratch dir must be creatable");
        dir
    }

    /// A file with `contents`, parents created. `name` may be nested.
    pub fn file(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.root.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("scratch parent must be creatable");
        }
        std::fs::write(&path, contents).expect("scratch file must be writable");
        path
    }

    /// A path inside the tree that deliberately does NOT exist, for the tests
    /// that check a missing file is reported rather than guessed at.
    pub fn absent(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let gone = release(&self.root);
        if std::thread::panicking() {
            return;
        }
        assert!(
            gone,
            "the guard failed to remove {} — the tree it owns must not outlive it",
            self.root.display()
        );
    }
}

/// The real `~/.termaxa/projects`, ignoring any `TERMAXA_HOME` override.
///
/// Deliberately not `paths::home_base()`: this has to name the directory the
/// override is protecting, which is exactly the one `home_base` stops
/// returning the moment the guard does its job.
fn real_state_root() -> Option<PathBuf> {
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))?;
    Some(PathBuf::from(home).join(".termaxa").join("projects"))
}

fn listing(dir: &Path) -> BTreeSet<OsString> {
    match std::fs::read_dir(dir) {
        Ok(entries) => entries.flatten().map(|e| e.file_name()).collect(),
        // Absent reads as empty on purpose: a directory that does not exist
        // yet and one that is empty are the same starting point, and the
        // comparison at drop is what has to notice the difference.
        Err(_) => BTreeSet::new(),
    }
}

/// Names present at drop that were not present at construction.
fn arrivals(before: &BTreeSet<OsString>, after: &BTreeSet<OsString>) -> Vec<OsString> {
    after.difference(before).cloned().collect()
}

pub struct TestEnv {
    /// `None` only for the tests in this module that already hold the lock in
    /// order to observe the guard without racing it.
    _lock: Option<MutexGuard<'static, ()>>,
    /// The tree and its cleanup. Dropped after this struct's own `Drop` runs,
    /// so the environment is already back to normal by the time the directory
    /// goes.
    tree: TempTree,
    previous_home: Option<OsString>,
    previous_cwd: Option<PathBuf>,
    watch: Option<(PathBuf, BTreeSet<OsString>)>,
}

impl TestEnv {
    /// Serialise against every other `TestEnv`, then claim a fresh tree.
    ///
    /// `label` only has to be readable in `/tmp` while a test is running; the
    /// pid and a counter make the path unique, so two tests sharing a label
    /// still get separate trees.
    pub fn new(label: &str) -> Self {
        Self::build(Some(lock()), label)
    }

    fn build(guard: Option<MutexGuard<'static, ()>>, label: &str) -> Self {
        let tree = TempTree::new(label);

        let previous_home = std::env::var_os("TERMAXA_HOME");
        std::env::set_var("TERMAXA_HOME", tree.path().join("home"));

        let watch = real_state_root().map(|dir| {
            let before = listing(&dir);
            (dir, before)
        });

        Self {
            _lock: guard,
            tree,
            previous_home,
            previous_cwd: None,
            watch,
        }
    }

    /// The tree this test owns. Everything it writes belongs under here.
    pub fn root(&self) -> &Path {
        self.tree.path()
    }

    /// Where `TERMAXA_HOME` points for the life of this guard.
    pub fn home(&self) -> PathBuf {
        self.tree.path().join("home")
    }

    /// A project directory with a minimal policy, ready for `resolve_from`.
    pub fn project(&self, name: &str) -> PathBuf {
        let proj = self.tree.path().join(name);
        std::fs::create_dir_all(proj.join(".termaxa")).expect("project dir must be creatable");
        std::fs::write(
            proj.join(".termaxa").join("policy.yaml"),
            "version: 1\ndefault: ask\nrules: []\n",
        )
        .expect("policy must be writable");
        proj
    }

    /// Move the process into `dir`, remembering where it came from.
    ///
    /// The original is captured once, so a test may step through several
    /// directories and still land back where it started.
    pub fn chdir(&mut self, dir: &Path) {
        if self.previous_cwd.is_none() {
            self.previous_cwd = std::env::current_dir().ok();
        }
        std::env::set_current_dir(dir).expect("cwd must be settable");
    }

    /// Watch a stand-in directory instead of the real one, so the check at
    /// drop can be tested without writing to anybody's home.
    #[cfg(test)]
    fn watch_instead(&mut self, dir: PathBuf) {
        let before = listing(&dir);
        self.watch = Some((dir, before));
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        // Step out before deleting: leaving the process in a directory that no
        // longer exists breaks `getcwd` for everything scheduled after it.
        if let Some(cwd) = self.previous_cwd.take() {
            let _ = std::env::set_current_dir(cwd);
        }
        match self.previous_home.take() {
            Some(previous) => std::env::set_var("TERMAXA_HOME", previous),
            // Restoring absence matters as much as restoring a value: a
            // variable left pointing at a deleted tree is the original bug.
            None => std::env::remove_var("TERMAXA_HOME"),
        }

        let strays = self.watch.take().map(|(dir, before)| {
            let found = arrivals(&before, &listing(&dir));
            (dir, found)
        });
        // The tree itself goes with `self.tree`'s own Drop, immediately
        // after this one.

        // Never assert into an unwind: a panicking Drop during a panic aborts
        // the process, and the test's own failure is the one worth reading.
        if std::thread::panicking() {
            return;
        }
        if let Some((dir, found)) = strays {
            assert!(
                found.is_empty(),
                "state landed outside this test's tree, in {}: {:?}\n\
                 The suite must not write where the product writes. If this is \
                 a new code path, route it through TERMAXA_HOME rather than \
                 widening this check.",
                dir.display(),
                found
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The anti-rot test. If `TestEnv` ever stops exporting `TERMAXA_HOME`,
    /// every test that trusts it keeps passing while writing to the real home
    /// again, which is precisely how the pollution went unnoticed for months.
    /// This is the one assertion that fails when the helper becomes a no-op.
    #[test]
    fn the_guard_actually_redirects_state() {
        let env = TestEnv::new("isolates");
        let paths = crate::paths::resolve_from(&env.project("proj")).expect("must resolve");
        assert!(
            paths.state_dir.starts_with(env.home()),
            "state must land under the guard's home, got {}",
            paths.state_dir.display()
        );
        assert!(paths.state_dir.join("logs").is_dir());
    }

    #[test]
    fn the_guard_puts_everything_back() {
        // Hold the lock across the whole test, so nothing else can move the
        // cwd or the variable between the guard dropping and the assertions.
        // The inner guard is built without taking it again, since a std Mutex
        // is not reentrant.
        let _outer = lock();
        let home_before = std::env::var_os("TERMAXA_HOME");
        let cwd_before = std::env::current_dir().expect("a cwd to return to");

        let root = {
            let mut env = TestEnv::build(None, "restores");
            let proj = env.project("proj");
            env.chdir(&proj);
            assert_ne!(
                std::env::current_dir().ok(),
                Some(cwd_before.clone()),
                "chdir must actually move the process"
            );
            assert_eq!(
                std::env::var_os("TERMAXA_HOME"),
                Some(env.home().into_os_string()),
                "the guard must export its own home while it is alive"
            );
            env.root().to_path_buf()
        };

        assert!(!root.exists(), "the guard must remove its own tree");
        assert_eq!(std::env::var_os("TERMAXA_HOME"), home_before);
        assert_eq!(std::env::current_dir().ok(), Some(cwd_before));
    }

    /// Run `f` with panic output silenced, and report whether it panicked.
    ///
    /// The guard reports by panicking, so a test that proves the guard works
    /// would otherwise print a wall of backtrace-looking text on a PASSING
    /// run, which is how people learn to ignore their own test output.
    fn panics_quietly(f: impl FnOnce() + std::panic::UnwindSafe) -> bool {
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = std::panic::catch_unwind(f);
        std::panic::set_hook(hook);
        outcome.is_err()
    }

    #[test]
    fn the_guard_fails_loudly_when_state_lands_outside_its_tree() {
        let _outer = lock();
        // The stand-in lives inside a guard of its own, so proving the check
        // works does not itself leave anything behind.
        let holder = TempTree::new("decoy-holder");
        let decoy = holder.dir("home-projects");

        let caught = panics_quietly({
            let decoy = decoy.clone();
            move || {
                let mut env = TestEnv::build(None, "stray");
                env.watch_instead(decoy.clone());
                // Stand in for a test resolving into the real ~/.termaxa.
                std::fs::create_dir_all(decoy.join("proj-deadbeef")).unwrap();
                drop(env);
            }
        });

        assert!(
            caught,
            "a test that writes outside its own tree must fail, not pass quietly"
        );
    }

    /// The check that keeps this the only obvious way.
    ///
    /// A guard that merely exists gets ignored: the six modules swept up in
    /// this PR each built temp paths by hand, and the pile in /tmp was the
    /// result. This fails at the moment somebody writes the line, naming the
    /// file, instead of months later when a stranger counts the directories.
    ///
    /// The earlier version of this check scanned the temp directory at every
    /// guard drop. It worked, and it cost 46ms per scan on a machine with
    /// 250k entries in /tmp: two seconds on a suite that otherwise runs in
    /// 0.06, paid only by developers, since CI runners start with an empty
    /// /tmp. Reading the source costs nothing and catches it earlier.
    #[test]
    fn no_module_builds_a_temp_path_by_hand() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders: Vec<String> = Vec::new();
        // Recursive, because a check that only reads the top level passes
        // silently the day src/ grows a subdirectory, and passing silently is
        // the failure mode this whole module exists to end.
        let mut queue = vec![src.clone()];
        while let Some(dir) = queue.pop() {
            for entry in std::fs::read_dir(&dir)
                .unwrap_or_else(|e| panic!("{} must be readable: {e}", dir.display()))
                .flatten()
            {
                let path = entry.path();
                if path.is_dir() {
                    queue.push(path);
                    continue;
                }
                if path.file_name() == Some(std::ffi::OsStr::new("testutil.rs"))
                    || path.extension() != Some(std::ffi::OsStr::new("rs"))
                {
                    continue;
                }
                let body = std::fs::read_to_string(&path).expect("source must be readable");
                for (i, line) in body.lines().enumerate() {
                    if line.contains("temp_dir()") {
                        let shown = path.strip_prefix(&src).unwrap_or(&path);
                        offenders.push(format!("{}:{}", shown.display(), i + 1));
                    }
                }
            }
        }
        offenders.sort();
        assert!(
            offenders.is_empty(),
            "these build a temp path by hand: {:?}\n\
             Use TempTree (or TestEnv, when TERMAXA_HOME matters) instead. \
             They clean up on their own, and a path nobody removes is how \
             /tmp filled up with 8,000 directories.",
            offenders
        );
    }

    #[test]
    fn the_check_only_reports_what_arrived() {
        let names =
            |xs: &[&str]| -> BTreeSet<OsString> { xs.iter().map(|s| OsString::from(*s)).collect() };
        // Pre-existing entries are somebody else's, and a test that removes
        // one is doing something worse than the check is looking for, but it
        // is not what this check is for.
        assert!(arrivals(&names(&["a", "b"]), &names(&["a", "b"])).is_empty());
        assert!(arrivals(&names(&["a", "b"]), &names(&["a"])).is_empty());
        assert_eq!(
            arrivals(&names(&["a"]), &names(&["a", "proj-deadbeef"])),
            vec![OsString::from("proj-deadbeef")]
        );
    }

    #[test]
    fn each_guard_gets_a_tree_of_its_own() {
        let first = TestEnv::new("unique");
        let first_root = first.root().to_path_buf();
        drop(first);
        let second = TestEnv::new("unique");
        assert_ne!(
            first_root,
            second.root(),
            "two guards sharing a label must not share a tree"
        );
    }
}
