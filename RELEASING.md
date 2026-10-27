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

9. Update the channels (after cargo publish), in this order, each verified
   from outside before the next:
   - Homebrew tap: a fresh clone of termaxa/homebrew-tap, branch
     termaxa-<v>, Formula/termaxa.rb with the version and the three sha256s
     computed from the downloaded release assets (never copy a hash you did
     not compute), commit "termaxa <v>", push, PR. The tap's own CI installs
     the formula on macOS and Linux; green there is the gate. The PR body
     names the version and the three hashes.
   - Scoop: a fresh clone of termaxa/scoop-bucket, bucket/termaxa.json with
     the version and the Windows hash, commit "termaxa <v>", push to main.
     `scoop update termaxa` on a Windows machine is the proof.
   - Site: termaxa/termaxa.com, branch site/v<v>, "Site for v<v>: the
     numbers": releases (the tag count), lines of Rust and of tests (step 2's
     command), tests, "v<v> today", the version block. PR, merge.
   - Playground: the Dockerfile's ARG TERMAXA_VERSION and ARG TERMAXA_SHA256
     (the Linux asset), commit "termaxa <v>", `flyctl deploy`, `flyctl
     status` (one machine started, 1 total, 1 passing). The build fails
     loudly if the hash does not match.
   - winget: the release workflow opens the PR on microsoft/winget-pkgs
     itself, from the devdoc83 fork, with a pinned komac (needs the
     WINGET_TOKEN secret; skipped, not failed, without it). Its validation
     runs the exe on a clean Windows, which found v0.21.4's VC++ runtime
     dependency and is the only such run we have. If the job fails:
     `wingetcreate update Termaxa.Termaxa --urls <new .exe url> --version <ver> --submit`
     by hand, then remove the `manifests/` folder it leaves in the working
     tree before committing anything.
   crates.io (step 7), the tap and Scoop are manual on purpose: publishing to
   package managers is the last human checkpoint before strangers' machines.

10. A security release: the advisory is a draft from the start, its affected
    range measured on the earliest releases that could carry it, and the fix
    lands through ordinary PRs. Publish only after crates.io, the tap, Scoop
    and the playground serve the fix and the playground answers the
    advisory's proof of concept with deny, because the playground runs the
    real gate in public. Request the CVE on the draft, publish, read the
    published page from outside with both version fields, then one docs PR
    for SECURITY.md's row (UTC dates, days exposed), and last the mail to
    whoever's report led to it. The README and the site state the policy,
    not a count, so a new advisory changes neither (Oct 28, 2026); the
    playground's solved challenge is optional.
