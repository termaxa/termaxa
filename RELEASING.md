# Releasing Termaxa

1. Land feature commits on main; wait for green CI.
2. Cut ONE release-prep commit containing:
   - CHANGELOG.md entry for the new version
   - Cargo.toml version bump (Cargo.lock updates on next build)
   - commit message = the release headline, e.g.
     "v0.12.0: plugin registry — termaxa add <tool>"
   This is the commit that gets tagged, so its message becomes the
   title of the tag-triggered Actions run.
3. Wait for green CI on that commit. Never tag red or in-flight runs.
4. Tag and push exactly that commit:
       git tag v0.12.0 && git push origin v0.12.0
   (Push the single tag, never `--tags`.)
5. The Release workflow gates on fmt+clippy+test, builds all four
   targets, and publishes once. Verify: four binaries + sha256s,
   one Full Changelog line.
6. Tags are immutable. A bad release is superseded by the next
   patch version, never retagged or deleted.
