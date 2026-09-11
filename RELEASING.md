# Releasing Termaxa

1. Land feature commits on main; wait for green CI.
2. Cut ONE release-prep commit containing:
   - CHANGELOG.md entry for the new version
   - Cargo.toml version bump (Cargo.lock updates on next build)
   - README's line counts recounted from the tree (Contributing section):
     production = every `src/*.rs` line before its `#[cfg(test)]` module;
     tests = those modules plus `tests/`. crates.io renders the README of
     the published crate permanently, so a stale number ships forever.
     (v0.18.0 shipped with counts from Aug 18.) Count with exactly this,
     in PowerShell — the marker must match the whole line, because an
     indented `#[cfg(test)]` on a test-only helper (audit.rs, preview.rs,
     resolve.rs, testutil.rs) is not the test module and moves ~480 lines
     if it is taken for one (v0.18.5):
       $prod=0; $tests=0
       Get-ChildItem src\*.rs | ForEach-Object { $l=[IO.File]::ReadAllLines($_.FullName); $i=[array]::IndexOf($l,'#[cfg(test)]'); if ($i -lt 0) { $prod+=$l.Count } else { $prod+=$i; $tests+=$l.Count-$i } }
       Get-ChildItem tests -Recurse -Filter *.rs | ForEach-Object { $tests+=[IO.File]::ReadAllLines($_.FullName).Count }
       "production $prod  tests $tests"
   - commit message = the release headline, e.g.
     "v0.12.0: plugin registry — termaxa add <tool>"
   This is the commit that gets tagged, so its message becomes the
   title of the tag-triggered Actions run.
3. Wait for green CI on that commit. Never tag red or in-flight runs. 
   - Before the release-prep commit, run the gate locally: cargo fmt --check, cargo clippy -- -D warnings, cargo test. Toolchain updates can fail CI on code you never touched — v0.12.0 hit fresh clippy lints in hook.rs and pg.rs that had been clean for weeks. Fixing that after tagging means untagging.
4. Tag and push exactly that commit:
       git tag v0.12.0 && git push origin v0.12.0
   (Push the single tag, never `--tags`.)
5. The Release workflow gates on fmt+clippy+test, builds all four
   targets, and publishes once. Verify: four binaries + sha256s,
   one Full Changelog line.
6. Tags are immutable. A bad release is superseded by the next
   patch version, never retagged or deleted.
7. After the GitHub release publishes, run cargo publish — otherwise cargo install termaxa lags behind the GitHub release.
   - Deliberately manual. crates.io publishes are permanent — a version can be yanked, never deleted or re-published with different content. GitHub releases can be edited or removed. Automating the irreversible step would remove the last human checkpoint before a permanent action, which is the argument this tool makes about destructive commands. The gate applies to us too.
8. After bumping Cargo.toml: run cargo build (updates Cargo.lock), then commit both Cargo.toml and Cargo.lock together in the release-prep commit, before tagging. Then tag → push → CI green → cargo publish.

9. Update the package managers (after cargo publish):
   - Homebrew tap: in termaxa/homebrew-tap, bump `version` and the three
     sha256s in Formula/termaxa.rb (sha256sum the downloaded release
     assets — never copy hashes you didn't compute). The tap's own CI
     installs the formula on macOS and Linux; green there is the gate.
   - winget: `wingetcreate update Termaxa.Termaxa --urls <new .exe url> --version <ver> --submit`
     (or bump the three manifests in the winget-pkgs fork by hand).
   Both are deliberately manual, same reasoning as step 7: publishing to
   package managers is the last human checkpoint before strangers' machines.
