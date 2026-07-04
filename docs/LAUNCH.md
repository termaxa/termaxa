# Launch Playbook — Termaxa v0.9

Everything for going public, in order. Work top to bottom.

---

## Before you touch GitHub — placeholders to replace

These strings appear across the repo and MUST be replaced before pushing:

- `termaxa` → your GitHub username/org (README badges, links; `src/init.rs` help text; workflows)
- `SECURITY-CONTACT@EXAMPLE.COM` → real security email (SECURITY.md)
- `LICENSE-APACHE` → swap the placeholder for full text:
  `curl -o LICENSE-APACHE https://www.apache.org/licenses/LICENSE-2.0.txt`
- `LICENSE-MIT` / `CHANGELOG.md` / license headers → set the copyright name
- Repo name: **not** bare `termaxa` (taken on crates.io; crowded on GitHub). Suggest `termaxa-agent` or `termaxa-gate`. The binary can still be `termaxa`.
- Scrub any real webhook.site URLs from docs/history before pushing.

---

## Step 1 — Papercuts ✓ (done in v0.9)

- Broken-pipe panic on piped output → fixed (SIGPIPE default on Unix).
- `--help` has a description + examples.
- Consistent output: decision/reason/preview blocks, `┌ └` boxes, `🛟` for backups.

## Step 2 — CI (`.github/workflows/ci.yml`) ✓ staged

Tests + build + a smoke test (benign allowed, `git status && rm -rf /` denied) on
Linux/macOS/Windows. **First push: watch it go green.** Then flip the clippy step to
`cargo clippy --all-targets -- -D warnings` and fix anything it flags. (Developed
without clippy available; the rustc build is warning-clean, but clippy is pedantic —
expect a few `needless_return`/`redundant_clone` style nits.)

## Step 3 — Release binaries (`.github/workflows/release.yml`) ✓ staged

```bash
git tag v0.9.0 && git push origin v0.9.0
```
Builds Linux x86_64, macOS x86_64 + arm64, Windows x86_64; attaches them to the
GitHub Release with generated notes. **macOS has never been built or tested locally —
the first release run is its first real test.** If the macOS job fails, that's
expected surface area; fix and re-tag `v0.9.1`.

## Step 4 — README ✓ staged

Hero line, 5-minute quick start, three demos (each verified to match real output),
Why-Termaxa (Claude Code prompt / sandbox / OPA), architecture diagram, honest limits.
Replace the demo code blocks with the actual GIFs once recorded (Step 6).

## Step 5 — SECURITY.md ✓ staged

Threat model, what it does NOT defend against, cooperative-interception boundary,
vulnerability reporting. This is the document infra developers check first — it's
deliberately honest to the point of listing its own bypass surface.

## Step 6 — Demo GIFs

```bash
# install vhs (https://github.com/charmbracelet/vhs), install termaxa, termaxa init in a demo dir
vhs demos/1-trench-coat.tape
createdb shop && psql -d shop -f demos/seed.sql && vhs demos/2-blast-radius.tape
vhs demos/3-rollback.tape
```
Then **record the hero**: a real Claude Code session hitting the gate on a force
push (screen capture, ~20s). This is the one that sells it.

## Step 7 — Five external install tests

The whole point: **you have never watched a stranger install this.** Find 5 people
(ideally: not Rust devs, on mixed OSes incl. one macOS and one Windows). Give them
ONLY the repo URL. Watch — don't help — and log every stumble.

Test script to hand them:
```
1. Read the README top. In one sentence, what does this do? (tests the hero line)
2. Install it however the README says. Time yourself. (target: under 5 min)
3. Run: termaxa init  in any folder with a git repo.
4. Run: termaxa check "git status && rm -rf /"
   Did it say deny? (if not — bug)
5. Run: termaxa check "git push --force origin main" in a repo with an upstream.
6. Tell me one thing that confused you.
```
Record: install time, OS, where they got stuck, the "what does this do" answers
(if they're wrong, the hero line is wrong). Fix the top 3 stumbles before Step 8.
Predictable finds: terraform preview never met real terraform; `rm` insurance vs
PowerShell aliases; PATH issues after `cargo install`.

## Step 8 — GitHub Release (v0.9)

- Tag pushed (Step 3), binaries attached, notes generated.
- README renders correctly (check the diagram in GitHub's font).
- LICENSE files present and real. CHANGELOG current.
- Issues enabled. A couple of "good first issue" labels (e.g. terraform real-world
  test, backup retention/pruning, Cursor adapter).

## Step 9 — Show HN

**Title** (state the artifact, not a slogan):
> Show HN: Termaxa – execution previews and automatic rollback for Claude Code

**First comment** (the origin story goes HERE, in maintainer voice — never in the title):

> I build with Claude Code daily and kept getting nervous handing it commands
> that touch git history and databases. The built-in "allow this command?"
> prompt tells you *what* it wants to run, not what will *happen* — so I built a
> gate that shows the consequence (this DROP hits 50k rows across 3 tables; this
> force push loses 1 commit), takes a backup first, and lets me roll back.
>
> The thing I didn't expect: the first time I pointed real Claude Code at it, the
> agent chained `git status && <destructive>` and slipped past a rule that only
> matched the prefix. Watching it happen live is why v0.7 splits compound
> commands and judges each part — that exact bypass is now a regression test.
>
> It's cooperative, not a sandbox: it governs the Claude Code hook and its own
> `run` command, not an agent actively trying to evade you (SECURITY.md is blunt
> about this). Rust, MIT/Apache, prebuilt binaries. Would genuinely like people
> to try breaking the policy matching — bypass reports are the best contribution.

**Timing:** Tue–Thu, ~8–10am ET. **Block 6 hours** to answer every comment fast;
responsiveness *is* the launch. Have the hero GIF ready to link.

**Prepared answers:**
- *"Why not just use Claude Code permissions?"* → previews + backup-before-approve + reason-fed-back; permission prompts don't do consequence or recovery.
- *"This is just a wrapper."* → true, and the value is in the previews/insurance/report, not the interception. The interception is deliberately simple.
- *"An agent can bypass this."* → yes, and SECURITY.md says so up front. Threat model is expensive mistakes, not adversarial evasion. Run a sandbox too.
- *"Does it work with Cursor/other agents?"* → CLI works anywhere; native hook is Claude Code today; adapters are a labeled good-first-issue.

## Step 10 — Domain (after HN, not before)

A single static page. It's a business card, not a funnel — people from HN Google
you later and just need to confirm you're real.

Content, nothing more:
- **Termaxa** — one line: "Run AI coding agents with confidence."
- The three-word triptych: **Predict · Protect · Recover**, each with one tiny
  terminal snippet (reuse the demo GIFs).
- Three buttons: **GitHub** · **Docs** (README) · **Install** (releases).

Host free: GitHub Pages from a `/docs` folder or a `gh-pages` branch. No tracking,
no email capture, no "book a demo." Ship it in an afternoon.

---

## The one-line status

v0.9, MIT/Apache, CI on 3 OSes, prebuilt binaries, honest SECURITY.md, three
verified demos. Real, tested, not oversold — exactly what this audience trusts.
