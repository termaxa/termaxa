# Changelog

All notable changes to Termaxa. Format loosely follows [Keep a Changelog](https://keepachangelog.com/); this project is pre-1.0, so minor versions may include breaking changes to the policy schema or CLI.

## v0.25.1 — a shell pattern where a rule has its `*` is matched by the rule

**In plain words:** a rule's `*` stands for anything, and the matcher tried it as an ordinary character first. Where the command line had a shell pattern at that place, the rule's `*` was used up on the pattern's own `*`, and the rule missed the line. With the starter, `echo x > /etc/*hosts` and `echo k > ~/.ssh/*_keys` were allowed by `echo *` from v0.15.0, the first release that judged a redirection, to v0.21.10, and bash and zsh write the one file each pattern matches. v0.22.0 began reading a word as the shell opens it, which refuses those two when the pattern matches a file. But a target that opens into more than 64 names is written out with only the names a deny rule could be about, and a rule written with the redirection operator, `*> /etc/*`, was never about a name on its own. So `echo x > /etc/*.d/*`, where that matches more than 64 files, was still allowed, and zsh, the default shell on macOS, writes every match; bash refuses such a redirection. A rule's `*` is now a wildcard first, and each name a target opens into is asked about where the line writes it. The matcher's fix reaches every rule, the allow rules too: `ls *.rs` and `cat *.md > notes.txt` asked, and are allowed by `ls *` and `cat *`, as those rules always said.

Security release for [GHSA-v26g-frcw-c2w6](https://github.com/termaxa/termaxa/security/advisories/GHSA-v26g-frcw-c2w6) (High), found on Nov 24, 2026 while running commands sent to the playground on a machine with more files under `/etc` than the playground has, and measured on each release's own binary with its own starter back to v0.6.1. One PR, #202.

### Security

- A rule's `*` is a wildcard wherever the line has a `*` of its own. `policy::wildcard_match` compared the two as characters before it tried the rule's `*` as a wildcard, so `*> /etc/*` did not match `echo x > /etc/*hosts` or `echo x > /etc/*.d/*`, and `*> ~/.ssh/*` did not match `echo k > ~/.ssh/*_keys` (#202).
- A name a redirection's target opens into is asked about where the line writes it, `> /etc/x.d/f`, as well as alone. Past 64 names a word keeps the ones a deny rule could be about, and none was kept for a rule written with the operator, so the line was judged as written. A line with more than 64 such names is refused now, as one with more than 64 that a path rule could be about already was (#202).
- The path rules that guard the gate's own files, the hook configs and `.env` were not affected: they are matched against each name a pattern opens into.

### Changed

- A line with a shell pattern where a rule has its `*` gets that rule. Over the 156 distinct commands sent to the playground and 17 ordinary lines with a pattern, with the starter, three verdicts change: `echo x > /etc/*.d/*` from allow to deny, and `ls *.rs` and `cat *.md > notes.txt` from ask to allow. `echo k > ~/.ssh/*_keys`, which v0.22.0 to v0.25.0 refused only where the pattern matched a file, is refused either way (#202).

### Measured and documented

- Each release's own binary with its own starter, v0.6.1 to v0.25.0, in a Linux container. Through v0.14.2 `echo x > /etc/hosts` itself is not refused. From v0.15.0 to v0.21.10 it is, and `echo x > /etc/*hosts` and `echo k > ~/.ssh/*_keys` are allowed. From v0.22.0 those two are refused, and a target under `/etc` that opens into 65 files is allowed while 64 are refused. On the v0.24.0 and v0.25.0 release binaries the 65 are allowed through `termaxa check` and through the hook, zsh 5.9 then writes all 65, and bash 5.2 writes none. This release refuses them in both.
- Asking about a name where the line writes it costs two strings per name: `echo x > /tmp/*` over 7,973 names takes 0.06 s on a release build of this tree, and 0.04 s on v0.25.0 (the median of five runs each).
- Not changed: under zsh a redirection that opens into several files writes every one of them, and the preview and the copy aside do not read them, so `echo x > out/*.txt` is allowed with no copy.
- 793 tests on Linux (3 new), 725 on Windows (722 at v0.25.0).

### Upgrade note

The fix needs nothing from a policy. A policy's own rules now match a line with a pattern where they have their `*`, as their text says: an allow rule `ls *` allows `ls *.rs`. Until the upgrade, a `match_path` rule for a directory, such as `match_path: "/etc/*"` with `action: deny`, refuses a redirection into it however many names it opens into.

## v0.25.0 — what a copy writes over is previewed and copied first, and `cmd /c` and `powershell -Command` are read

**In plain words:** `cp -r backend/* /opt/proxypilot/backend/` is the command behind #12: it dragged a development virtualenv over a production one, and termaxa 0.24.0 said nothing about it, because a copy into a directory was read as where files land, not as what is lost. This release reads what a copy, a move, an rsync or an unpacked archive writes over, and what `rsync --delete` removes. Where the delete preview's warning signs are on those files (outside the project, directly in a user profile, a credential's name, more than the copy can take), the preview names them and the copy aside takes them first, so `termaxa rollback` brings them back; an ordinary copy inside the project still says nothing. A `cp` or an `mv` onto an existing file is copied first too, as the README's table had said of `cp` all along. The path rules see what an rsync, a zip or a tar touches, so with the starter none of them removes or writes the gate's own files; a compressed archive is not read. A command handed to `cmd /c` or `powershell -Command` is read as the command it runs. And the copy aside no longer loses one of two files that share a name.

Eight PRs: #199 and #200 for #12; #197 for the Windows shells' strings (#64); #193, the links a delete meets (#7); #194, a quoted Windows path; #198, two paths with one name in the copy aside; #195 and #196 for the tests, a race in a stub and four integration files running on Windows (#59).

### Added

- What a copy or a move writes over is read (#199): `cp`, `mv`, cmd's `copy` and `move`, `Copy-Item`, `Move-Item` and `git mv`. Each file of the sources is placed where it lands, and a file there now is written over. A tree is read from its own files and, past the budget, from the directory it lands in, which is exact while that directory is small. Where the destination is a file, it is previewed as before and now copied first; where it is a directory, the files it replaces are previewed and copied first only when a sign is on them, so `cp -r src/* dist/` says nothing. A copy writes through a link at the destination to the file it points to (GNU coreutils 9.4), and that file is what is copied; a move replaces the link. The summary an agent's prompt shows leads with the sign.
- rsync and unpacked archives are read (#200). rsync as measured on 3.2.7: a source written with a trailing separator lands its contents, one written without lands under its own name whether or not the destination is there, `--delete` removes what the destination holds and no source has, `--exclude` keeps what it matches, and a link where a file lands is replaced. An archive unpacked by `tar -x`, `unzip` or `Expand-Archive` is read for its member names, from a zip's central directory or a tar's headers and never by unpacking it, with the tools' own `-C`, `-d`, `--strip-components`, `-j`, `-k`, `-n`, `-o` and `-Force` (GNU tar 1.35, UnZip 6.00, and Microsoft's documentation of `Expand-Archive`). A compressed tar is not read, because the gate carries no decompressor: the preview says which compression it met and that anything at the destination may be written over. What is written over and what is removed are previewed and copied first where a sign is.
- The path rules see what an rsync lands and removes, and every member an unpacking lands, in the project and in an agent's configuration under the home directory (#200).
- A string handed to `cmd /c` or `/k`, or to `powershell` or `pwsh` with `-Command` (or `-c`, or a prefix of three letters or more), is read as the command it runs, as a POSIX shell's `-c` string has been since v0.17.1 (#197). cmd's own rule for the quotes around its string is followed, and under the cmd and PowerShell readings on Windows the string is respelled as those shells read it. A script file, `-File`, `-EncodedCommand` and `-Command -` are not read.
- The delete preview names the links it meets (#193). A delete of a link says whether it removes the link or reaches what the link points to: for `rm`, `unlink` and `git rm` on unix a trailing slash is the whole difference (GNU coreutils 9.4), and for every other command, and every command on Windows, the link is named with a warning and what it points to is counted and copied. Links inside a deleted tree are counted, and the first is named with its target.

### Changed

- A `cp` or an `mv` onto an existing file was uninsurable, so an explicit `ask` on it was amplified to a refusal, and observe mode held a deny on it: with the starter on v0.24.0, `cp notes.md sub/.env` was held with no copy, while `echo x > sub/.env` ran after its copy. It is copied first now, the ask stays an ask, and observe mode runs it after its copy (#199).
- A flagged copy, rsync or unpacking past the copy budget is "NOT recoverable", which makes an explicit `ask` on it a refusal, as for a delete past the budget (#199, #200).
- With the starter, an `rsync --delete` from a template without the gate's files, and an unpacking of an archive that holds `.claude/settings.json`, are refused in every mode by the files they touch, where they asked (#200).
- The Windows shells' strings decide (#197): `powershell.exe -Command echo hi` and `powershell -Command "Get-ChildItem"` are allowed by the rules that allow `echo` and `Get-ChildItem`, where they asked; `cmd /d /s /c "rd /s /q build"` is allowed as `rd /s /q build` is; `cmd /c "del notes.txt"` and `powershell -Command "Remove-Item notes.txt"` still ask, now with a preview and a copy aside.
- A sensitive name is the name in any casing, or the name with more after a `.` or a `_` (#199). The delete preview no longer calls `.gitignore` and `.github` "git history", or `.dockerignore` "Docker credentials".
- The preview's and the backup's lexers read a backslash inside double quotes as bash does (#194): it escapes `"`, `\`, `$`, a backtick and a newline, and stays before anything else. Under an `except_rebuilt` deny, `rm -rf "node\_modules"` was allowed and is refused: every shell deletes `node\_modules`, which nothing rebuilds.

### Fixed

- The copy aside put two paths with one name in one place, the second over the first: on v0.24.0, `rm a/config.json b/config.json` reported "2 path(s) copied" and `rollback` put `b`'s content in both. Each path has a place of its own now, and a record written before restores as it did (#198).
- A quoted Windows path, `rm "C:\Users\me\x\notes.txt"`, was previewed as `C:Usersmexnotes.txt`, "nothing to delete", and nothing was copied; it is previewed and copied as itself (#194).
- `rm -r old/link/`, which GNU rm resolves to empty the directory behind the link, was insured with a copy of the link alone; it is insured with what the link points to (#193).

### Measured and documented

- On the v0.24.0 release binary, with the starter: `cp -r backend/* <outside>/backend/`, and `cp a.txt d/` onto an existing `d/a.txt`, had no preview; `cp a.txt b.txt` onto an existing `b.txt` was a loss no backup covered; `rsync -a --delete tpl/ ./`, and `tar -xf` or `unzip -o` of an archive holding `.claude/settings.json`, asked with "no rule matched". With a build of this release and the real tools under an allow rule, the incident's shape, `rsync -a --delete build/ <outside>/`, `tar -xf rel.tar -C <outside>` and `unzip -o rel.zip -d <outside>` each copied first what they wrote over and removed, ran, and `rollback` put every file back.
- Not read: `install`, `ln`, `find -exec`, `robocopy` and `xcopy`; a compressed archive; an rsync from or to another machine, or with `-R`; PowerShell's `-File` and `-EncodedCommand`. SECURITY.md says what is read and what is not.
- The tests: pg's stub programs wait out the exec race (#195); the stub `psql` is a program that builds on every platform, and `cli_surface`, `init_output`, `doctor_output` and `hook_dialects` run on Windows, with only the tests that need unix gated (#196). 790 tests on Linux (33 new), 722 on Windows (649 at v0.24.0).

## v0.24.0 — Hermes Agent: its calls judged, its wiring written by `init` and held by the floor

**In plain words:** Hermes Agent runs shell hooks that a profile's `config.yaml` declares, for every session the profile serves, and termaxa 0.23.0 read none of its calls: in a Hermes session with the released hook wired in, and Hermes's own approval set aside, `rm -rf src` ran. This release reads them (`termaxa hook --hermes`), wires them (`termaxa init --hermes`, checked by `doctor`), and holds that wiring on the floor, so an agent cannot unhook the gate by editing Hermes's configuration or revoking its approval. Hermes does not say which project a call belongs to, so every Hermes call is judged by one policy in termaxa's home. A deny blocks in every mode. An ask goes to Hermes's own approval prompt and names the call, except under `--yolo` or `hermes -z`, where Hermes approves it itself. It was tried live on Windows with Hermes 0.23.3 before the release, and that run found two defects, fixed here.

Five code PRs for Hermes: #186, its dialect; #187, `init --hermes` and `doctor`; #188, the floor; #189, receipts; #190, asks. #185 gives the Claude Code plugin its icon, and #191 fixes a race in the supervised-mode boundary rig.

### Added

- Hermes Agent's dialect, `termaxa hook --hermes` (#186). Hermes sends `pre_tool_call` and `post_tool_call` with `tool_name`, `tool_input`, `session_id`, `cwd`, `profile` and an `extra` of ids. Its shell, `terminal`, is judged as a command; `write_file` and `patch` go to the native-write reader; `execute_code`, whose Python cannot be read, is an ask. A deny is `{"decision":"block","reason":…}` with exit 2, an ask is `{"action":"approve","message":…,"rule_key":…}` for Hermes's approval gate, an allow is silence, and a `post_tool_call` for a call that ran is a receipt. Hermes's `cwd` is the gateway's own directory (NousResearch/hermes-agent#146570) and a terminal call's `workdir` is the agent's to choose, so neither picks the policy: every Hermes call is judged by `hermes/.termaxa/policy.yaml` in termaxa's home, or by the built-in starter while there is none, with one record. A directory is read only for where a command's paths land; with none known, a path rule matches a path by its end and only a path given in full is previewed and copied, and the reason says so. Without `--hermes`, a Hermes call is refused, and the reason names the flag.
- `termaxa init --hermes` (#187) wires the profile a bare `hermes` uses: the one `HERMES_HOME` names, or else `~/.hermes` (`%LOCALAPPDATA%\hermes` on Windows) or the profile its `active_profile` file names. It writes the Hermes policy from the starter when there is none and records its fingerprint; adds the hooks to `config.yaml` (`pre_tool_call` on `terminal`, `write_file`, `patch` and `execute_code`, with `fail_closed`; receipts on `post_tool_call`), keeping the file as it was beside it; approves both in `shell-hooks-allowlist.json`, as `hermes --accept-hooks` would; and sends the command a test call. A `config.yaml` with hooks of its own is not edited: the entries to add are printed, and a second run approves them. On Windows the command is the binary's full path. `--observe` works with it. `termaxa doctor` has a Hermes Agent line: the entry, its matcher, the approval, the command's answer to a test call, `fail_closed`, the receipts, the profile and the policy's fingerprint.
- A receipt only for a Hermes call that ran (#189). Hermes sends `post_tool_call` after every call, the refused ones included, and says in `extra.status` what became of it. A receipt after an ask is read as a person's yes by the circuit breaker and by `termaxa report`, so termaxa keeps one only for `ok`, or for a terminal call's `error` that carries the command's own exit code. Asks refused one after another add up to a trip, as for every other agent.
- A Hermes ask names its call and carries a `rule_key` for that call alone (#190). Hermes's prompt shows the hook's message under a label of its own; the message now says first what the call is (the command, the paths a write names, or the start of the Python, on one line, cut at 120 characters, with a control character or one that reorders text shown as `?`). Hermes keeps a standing answer ("Allow for this session", "Add to permanent allowlist") under the ask's key, so it allows the same call again and nothing else.
- The Claude Code plugin's icon, `.claude-plugin/icon.png` in the plugin's folder: the site's mark at 1024 × 1024, for the plugin directory (#185). The folder changed, so the plugin's version is 0.1.1; it still runs `termaxa` 0.23.0 or later.

### Changed

- The starter holds Hermes's wiring as it holds every other agent's hook configuration, in every mode (#188). A profile's `config.yaml` and `shell-hooks-allowlist.json`, in Hermes's home and in a named profile's (`profiles/<name>`), are refused by what a command touches (four `match_path` rules), by a string rule for a program the gate cannot read (two, with `except_reads`) and from a file tool. `hermes hooks revoke` (or `remove`, or `rm`) and `hermes config set`, `unset` and `edit`, which rewrite `config.yaml` through Hermes's own code, are refused (seven string rules, with `except_reads`). `HERMES_HOME` is read as a moved directory, as `CLAUDE_CONFIG_DIR`, `CODEX_HOME` and `TERMAXA_HOME` are, and so is Hermes's own default where it is not called `.hermes`. Reading those files is ordinary work, and the rest of Hermes's home (its skills, memories and sessions) is Hermes's own. The starter has 249 rules (162 allow, 14 ask, 73 deny), 58 of them on the floor; `examples/policy.yaml` and this repository's own `.termaxa/policy.yaml` follow.
- The starter's comment over the broad recursive-force deletes no longer says that `ask` degrades to `allow` under auto-approving agent UIs, which Claude Code's auto mode disproves. It says where an agent answers an `ask` itself (Cursor's Auto-review, Hermes under `--yolo` or `-z`) and that a deny holds in every one. No verdict changes.

### Measured and documented

- Live on Windows with Hermes 0.23.3 and a real model (Nov 22, 2026): a refusal reached the agent in termaxa's words; an ask reached the person at Hermes's prompt; with `termaxa` moved aside, Hermes refused the call itself, under `fail_closed`; and a `write_file` to a profile's `config.yaml` was refused, after which the agent would not try another tool. The run found #189 (a receipt for a refused call) and #190 (an ask that did not name its call, and a standing answer that covered the whole tool), each fixed before this release.
- `hermes -z` (Nov 22, 2026, Hermes 0.23.3 on Windows): Hermes runs a one-shot turn as one nobody can answer and approves its asks as `--yolo` does, so an ask for `hostname` ran with no prompt and kept its receipt, while `rm -rf` was still refused. `hermes chat -q` refused the same ask, as `approvals.single_query_mode: deny`, Hermes's default, says it will.
- Claude Code, for anthropics/claude-code#111218, a report that a background session ran a command its hook had asked about (2.1.328): on 2.1.330 a `claude --bg` session in auto mode held termaxa's ask as an approval waiting in `claude agents`, and nothing ran. SECURITY.md's entry on whether an `ask` reaches a human has it, and names Hermes beside Cursor's Auto-review as harnesses that answer an ask themselves.
- The supervised-mode boundary rig waits for its supervisor to say that its socket is open, and fails, with the hook's reason, on a refusal the supervisor never made (#191).
- docs/dialects.md has Hermes's capture, its answers, its prompt and receipts, the directory and the wiring, and names `--hermes` in its table where it said the wiring was by hand. SECURITY.md has a design bullet for Hermes, and its sentence on Tim Schipper's corpus no longer says that every agent UI answers an `ask` for you. Both READMEs have Hermes's row in the harness table and a sentence in the quick start, and say what the hash-chained record proves in each mode, where they said the agent cannot rewrite it, which holds in supervised mode only. 757 tests on Linux (34 new), 649 on Windows.

### Upgrade note — Hermes, and a policy from before v0.24.0

`termaxa init --hermes` writes the Hermes policy from this release's starter. A Hermes policy written from `main` before this release has the file guard and not the command rules: delete `hermes/.termaxa/policy.yaml` under termaxa's home and run `termaxa init --hermes` again.

A project policy from before v0.24.0 holds Hermes's files from a file tool, with no change, but not from a command. Where an agent of another harness can reach Hermes's home, paste these thirteen rules at the top of `rules:` to have it refuse a command too:

```yaml
  - match_path: "*/.hermes/config.yaml"
    action: deny
    reason: "Hermes's hook configuration is off limits — editing it unhooks the gate."
    floor: true
  - match_path: "*/.hermes/shell-hooks-allowlist.json"
    action: deny
    reason: "Hermes's hook configuration is off limits — editing it unhooks the gate."
    floor: true
  - match_path: "*/.hermes/profiles/*/config.yaml"
    action: deny
    reason: "Hermes's hook configuration is off limits — editing it unhooks the gate."
    floor: true
  - match_path: "*/.hermes/profiles/*/shell-hooks-allowlist.json"
    action: deny
    reason: "Hermes's hook configuration is off limits — editing it unhooks the gate."
    floor: true
  - match: "*.hermes*config.yaml*"
    action: deny
    reason: "Hermes's hook configuration is off limits — editing it unhooks the gate."
    floor: true
    except_reads: true
  - match: "*.hermes*hooks-allowlist*"
    action: deny
    reason: "Hermes's hook configuration is off limits — editing it unhooks the gate."
    floor: true
    except_reads: true
  - match: "*hermes* hooks* revoke *"
    action: deny
    reason: "Revoking a Hermes hook's approval turns the hook off, and this gate is one. Do it yourself."
    floor: true
    except_reads: true
  - match: "*hermes* hooks* remove *"
    action: deny
    reason: "Revoking a Hermes hook's approval turns the hook off, and this gate is one. Do it yourself."
    floor: true
    except_reads: true
  - match: "*hermes* hooks* rm *"
    action: deny
    reason: "Revoking a Hermes hook's approval turns the hook off, and this gate is one. Do it yourself."
    floor: true
    except_reads: true
  - match: "*hermes* config* set *"
    action: deny
    reason: "Hermes's config.yaml declares its hooks, and this gate is one of them. Change it yourself."
    floor: true
    except_reads: true
  - match: "*hermes* config* unset *"
    action: deny
    reason: "Hermes's config.yaml declares its hooks, and this gate is one of them. Change it yourself."
    floor: true
    except_reads: true
  - match: "*hermes* config* edit"
    action: deny
    reason: "Hermes's config.yaml declares its hooks, and this gate is one of them. Change it yourself."
    floor: true
    except_reads: true
  - match: "*hermes* config* edit *"
    action: deny
    reason: "Hermes's config.yaml declares its hooks, and this gate is one of them. Change it yourself."
    floor: true
    except_reads: true
```

Then run `termaxa init`, which is how `doctor` is told that the edited policy is the one you mean, and `termaxa check "hermes hooks revoke pre_tool_call"` should say `deny`.

## v0.23.0 — the Claude Code plugin, and `init` proposes a watched project's own rules

**In plain words:** v0.22.0 gave Claude Code a hook that a plugin could register for every project on the machine, watching a project that has no policy, and nothing registered it yet. This release is that plugin. It lives in this repository, which is its own marketplace, so `/plugin install termaxa --marketplace termaxa/termaxa` puts the gate on every project you open in Claude Code (2.1.275 or later; on an earlier version, `/plugin marketplace add termaxa/termaxa` and then `/plugin install termaxa@termaxa`). A plugin registers hooks that run as the session does, and this gate can be one of them, so the floor now holds the plugin as it holds the settings file: an agent cannot turn it off, uninstall it, or rewrite what Claude Code installed. And the record of a watched project has a use: `termaxa init` reads it and proposes the project's own rules, each with how often it asked, for you to take or leave.

Two code PRs: #182, `init` proposing rules; #183, the plugin and its guards.

### Added

- The Claude Code plugin, in [`claude-code-plugin/`](claude-code-plugin/), with the repository's marketplace in `.claude-plugin/marketplace.json`. It holds no program and no script: it registers `termaxa hook --plugin` for `SessionStart`, and for `PreToolUse` and `PostToolUse` on the matchers `termaxa init` registers, and runs the `termaxa` you installed, which has to be this release or later. In a project with no policy it watches: a line at the start of the session says so, nothing is asked and nothing is approved, and only the floor is refused. A project with a policy is judged by it, and a project that registers `termaxa hook` itself is left to that hook. Its README says what it runs, sends and fetches. Its version, 0.1.0, is its own: Claude Code updates an installed plugin when that version changes (#183).
- `termaxa init` reads the record a plugin's hook kept for the project and proposes the project's own allow rules before it writes the policy. What is proposed is what asked because nothing in the starter decided it. Each proposal names the action as it was typed (`npm run build`, `npx prisma generate`, followed by ` *` when it took arguments) and never a runner on its own, with how often it asked and the commands themselves. At a terminal each one is put to you, `y` to take it; with no terminal, as when an agent runs `init`, each is written as a comment that changes no verdict until you take the `# ` off and run `termaxa init` again. Rules you take go below every rule of the starter, so the floor and every refusal keep their place. Not proposed, and listed by why: a command that removes, overwrites or discards files, one whose own words delete or destroy, an install of a package named on the line, anything run as another user, code given on the line, a database client's statements, and anything that asked once. `init` also says to restart a Claude Code session already open in the project (#182).

### Changed

- The starter holds Claude Code's plugins as it holds the settings file, in every mode. A write or a removal under `.claude/plugins/`, where Claude Code keeps the registry of installed plugins, the marketplaces it knows and a copy of each plugin with its `hooks/hooks.json`, is refused by what a command touches (`match_path: "*/.claude/plugins/*"`), by a string rule for a program the gate cannot read (`*.claude*plugins*`, with `except_reads`), and from a file tool. So are `claude plugin disable`, `claude plugin uninstall` or `remove`, and `claude plugin marketplace remove` or `rm`, however the program is named or wrapped (five string rules, with `except_reads`). Any plugin, not only this one, as the settings file is held whole and not only its hooks. A `CLAUDE_CONFIG_DIR` elsewhere is read under its default name, as for the settings. Reading those files, and listing, installing, enabling or updating a plugin, are left to the policy. The starter has 236 rules (162 allow, 14 ask, 60 deny), 45 of them on the floor; `examples/policy.yaml` follows (#183).

### Measured and documented

- In a Claude Code session on Windows (2.1.266, Nov 18, 2026, auto mode), with the plugin installed from its pull request's branch and that build of `termaxa`: the session's line was shown at the start; `ls` ran with nothing said; `find . -name "*.tmp" -delete`, `claude plugin disable termaxa@termaxa` and a `Write` to `.claude/plugins/test.json` were each refused with the rule's sentence, which the agent read before it stopped. With no `termaxa` on PATH, Claude Code showed a hook error at the start and two on every call, ran every command, and told the agent nothing: until `termaxa` is installed, nothing is watched or refused.
- The guards, watched, on the released 0.22.0 and on a static build of this release, with Claude Code's configuration directory under its own name and under another: of 32 lines that turn a plugin off or rewrite what Claude Code installed (14 commands, 15 writes through the shell, 3 from file tools), 0.22.0 refuses 1, an `rm -rf` of a path spelled with a variable, held because nothing could be copied first, and this release refuses 32. 11 ordinary lines (listing, reading, enabling and validating plugins, installing another, a `grep` and a commit message that name the command) get no answer on either.
- Ordinary work is answered as before: watched, the 95 everyday calls, the 304 floor lines and the 112 directory lines, call for call as 0.22.0 answers them; and through `termaxa check` with the built-in starter, the 84 shell commands among the 95 (33 allow, 34 ask, 17 deny on both).
- `termaxa init` on the record of the 95 everyday calls, watched: 89 commands, 34 that would have asked and 22 refused. It proposes two rules (`npm install` and `npm run build`, each asked twice), lists the rest under why it does not, and the two taken at a terminal would have let 4 of the 34 asks run.
- Claude Code 2.1.327 and 2.1.266 install the plugin from this repository (`claude plugin marketplace add termaxa/termaxa`, then `claude plugin install termaxa@termaxa`), and 2.1.327 in one step (`claude plugin install termaxa --marketplace termaxa/termaxa`); `claude plugin validate --strict` passes on the plugin and on the marketplace.
- docs/observe-mode.md says how the plugin is installed and what the floor holds of it, and SECURITY.md has a design bullet for it. 723 tests on Linux (16 new), 615 on Windows.

### Upgrade note — a policy from before v0.23.0

`init` never rewrites a policy, and a policy written before this release does not hold the plugin. To have it do so, paste these seven rules at the top of `rules:`:

```yaml
  - match_path: "*/.claude/plugins/*"
    action: deny
    reason: "Claude Code's plugin files decide which hooks run, this gate's among them. Change them yourself."
    floor: true
  - match: "*.claude*plugins*"
    action: deny
    reason: "Claude Code's plugin files decide which hooks run, this gate's among them. Change them yourself."
    floor: true
    except_reads: true
  - match: "*claude* plugin* disable"
    action: deny
    reason: "Turning off or removing a Claude Code plugin turns off its hooks, and this gate can be one of them. Do it yourself."
    floor: true
    except_reads: true
  - match: "*claude* plugin* disable *"
    action: deny
    reason: "Turning off or removing a Claude Code plugin turns off its hooks, and this gate can be one of them. Do it yourself."
    floor: true
    except_reads: true
  - match: "*claude* plugin* uninstall *"
    action: deny
    reason: "Turning off or removing a Claude Code plugin turns off its hooks, and this gate can be one of them. Do it yourself."
    floor: true
    except_reads: true
  - match: "*claude* plugin* remove *"
    action: deny
    reason: "Turning off or removing a Claude Code plugin turns off its hooks, and this gate can be one of them. Do it yourself."
    floor: true
    except_reads: true
  - match: "*claude* plugin* rm *"
    action: deny
    reason: "Turning off or removing a Claude Code plugin turns off its hooks, and this gate can be one of them. Do it yourself."
    floor: true
    except_reads: true
```

The file tools are held from `.claude/plugins/` with no change to the policy. Then run `termaxa init`, which is how `doctor` is told that the edited policy is the one you mean, and `termaxa check "claude plugin disable termaxa@termaxa"` should say `deny`.

## v0.22.0 — a write is judged however the shell spells it, and a plugin's hook watches a project that has no policy

**In plain words:** a rule names a file, and the gate read a command line one way: quotes as a POSIX shell has them, and every other character as part of the name it spells. A shell reads more into a line before the command runs. bash takes a backslash out of a word, so `.ter\maxa` is `.termaxa`, and spells any character by its number inside `$'...'`; cmd does the first with a caret and PowerShell with a backtick. Every shell opens a word with a pattern in it (`.clau[d]e`, `.cl*`) into the names it matches on disk, bash and zsh open a brace list or a range (`.claud{e..e}`), and zsh reads a group (`.claud(e)`) as a pattern too. Four ways of sending output to a file, `&>`, `>&`, `&>>` and `<>`, were read as no file at all, and a quote inside a target (`".claude"/settings.json`) stayed part of the name. With the starter, `echo x > .ter\maxa/policy.yaml`, `echo x > .clau[d]e/settings.json`, `echo x > .claud{e..e}/settings.json` and `echo x &> .claude/settings.json` were allowed by `echo *`: a write to the gate's own policy, or to the file the gate is registered in. And a directory that its tool had moved (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `TERMAXA_HOME`) was guarded under its default name only. In observe mode, where the floor is the one thing held, all of these ran. A line is now judged as each shell that can run it reads it, each word as the shell opens it, a redirection however it is spelled, and a moved directory like the one it replaces. Apart from that, `termaxa hook --plugin` is the hook a plugin will register for every project on the machine: in a project with no policy it watches, holding the floor and recording the rest, and where the project wires its own hook it stands down.

Security release for [GHSA-x6qc-h3gm-5fj2](https://github.com/termaxa/termaxa/security/advisories/GHSA-x6qc-h3gm-5fj2) (High), the spellings, and [GHSA-vh3g-qw73-h9gg](https://github.com/termaxa/termaxa/security/advisories/GHSA-vh3g-qw73-h9gg) (High), the moved directories. The moved directories were found on Nov 15, 2026 while building the plugin's hook, the redirections the same day while measuring another change, the escapes while measuring the redirection fix, and the patterns on Nov 16 while measuring the escapes; each was measured on each release's own starter back to v0.6.1. Four code PRs: #176 the redirections, #177 the moved directories, #178 the shell readings, #179 the opened words; #175 is the watching. The advisories list when each form started.

### Security

- A redirection is a write however it is spelled. `&> file`, `&>> file` and `>& file` send both streams to a file and are read as the `>` or `>>` they are, and `<> file` as a write that does not truncate; `2>&1`, `>&2`, `>&-` and a sink name no file, as before. A target's quotes are taken off wherever they stand in the word, so `".claude"/settings.json` is `.claude/settings.json` (#176).
- `except_reads` stops at the line's first redirection: a rule that says it still applies if it matches the line from its first `>` outside quotes on, found by text and nothing else, so that it holds where the reader is wrong again. `echo x > "$(echo .claude)/settings.json"`, a target no reader can resolve, is refused by the string again, as on v0.21.9; `echo "see .claude/settings.json" >> TODO.md`, a mention ahead of a redirection into another file, is excepted, as on v0.21.10 (#176).
- A directory its tool has moved is guarded like the one it replaces. A path inside the directory `CLAUDE_CONFIG_DIR`, `CODEX_HOME` or `TERMAXA_HOME` names is read under the default name (`.claude`, `.codex`, `.termaxa`) as well: by the file-tool guard, by every path rule and, for a deny, by the string rules. Where the hook's environment has a value, the variable itself is the directory (`$CLAUDE_CONFIG_DIR/settings.json`, `%TERMAXA_HOME%\x`); where it has none, a path read only at its end counts when the end starts with the directory's own last components. A tree deleted, moved or copied over one of the two agent directories is judged by the settings file inside (#177).
- A line is judged as each shell that can run it reads it: as typed, as bash reads it, and on Windows as cmd and PowerShell read it. A deny by a rule from any reading refuses the line, and the reason says whose reading it is; nothing else is taken from a reading. bash takes a backslash outside quotes out of a word, keeps one inside double quotes except before `$`, a backtick, `"`, `\` and a newline, and decodes `$'...'`; cmd takes a caret out, and PowerShell a backtick, where a letter it makes a control character of (`` `a ``, `` `n ``) is not that letter; to cmd and PowerShell a backslash is an ordinary character, so a `|` or a `"` after one is what it is. A string a wrapper hands to a shell (`sh -c '...'`, `eval '...'`) is read the same way at every depth (#178).
- A word is judged as the shell opens it. Each segment of each reading is judged as written and as the shell hands it to the command: brace lists and ranges opened, then `*`, `?` and `[...]` matched on disk from the directory the segment runs in, in any component, a name that starts with a dot only by a pattern that starts with one, and `**` as any number of directories; zsh's group `(a|b)`, and bash's behind `@`, `?`, `+`, `*` or `!`, as a pattern of alternatives. A pattern that matches nothing is handed over as written, as the shell hands it. `shopt -s dotglob`, `globdots` and `nocaseglob` count where the line names them, `$PWD` and `~+` are the segment's directory, and a variable's literal default (`${X:-.clau[d]e}`) is read as one spelling the line may have (#179).
- A `cd` whose word the shell opens goes where the shell goes: to the one directory the word opens into, to the word as written when a bracket or a brace matches nothing (`cd app/[id]`), and nowhere known when it opens into several names or a file (#179).
- The exceptions a policy writes are kept. A deny that stood aside for the line as typed, one that says `except_rebuilt` on a delete of what a build rebuilds or one below an allow that matched first, stands aside for its readings and its opened words, so `rm -rf node_modules\.cache` and `rm -rf dist/*` are judged as before. `except_reads` is asked of each reading afresh, and a path rule has no exceptions (#178, #179).
- The preview and the copy aside are made for what a rule refuses: the reading or the opened segment, in the directory it runs in. Observe mode holds a line whose copy cannot be taken, and asks that of the file the shell would write: `cp notes.md sub/.en[v]` is held as `cp notes.md sub/.env` is (#178, #179).
- A word that opens into more than can be read is refused in every mode, as a command the reading stopped short of is: past 100,000 words, past 64 that a rule could be about, or past a second of asking which those are (#179).

### Added

- `termaxa hook --plugin`, the hook a plugin will register for every project on the machine. Nothing registers it yet; the plugin is a later change. In a project with no `.termaxa/policy.yaml` it watches: the built-in starter judges each command and each native write in observe mode, whatever `TERMAXA_MODE` says, the floor is refused, and nothing is said for anything else. The gate's own files are on the floor, so a watched session cannot write the policy, or the hook registration, that would end the watching. The record, the witness and the copies are kept in the state directory a later `init` at the checkout's root resolves to, lines carry `mode: watch`, a session is told once at its start, and the circuit breaker does not run. A project that has a policy is judged by it as written, in its own mode. Where the project's `.claude/settings.json` or `settings.local.json`, or the user's `settings.json`, has registered `termaxa hook` under `PreToolUse` for ten seconds, it answers nothing and records nothing, so that no command is judged twice. Without the flag the hook is what it was (#175).

### Changed

- `report`, `log`, `stats`, `backups`, `rollback` and `paths` read a watched project's record from inside it, and `doctor` says a project is watched. The report's `Asks` line counts the asks that were put to somebody. It counted an observed ask too, with the command's own receipt for the answer, so six observed asks came out as "Asks 6, approved 6" and the insight proposed an allow rule for a habit nobody had; the count has had no eye for the mode since observe mode shipped in v0.20.0. An ask recorded and not enforced is now in the observed section only, and `log` marks it `→ observed, not enforced` or `→ watched, not enforced` (#175).
- A file behind `&>`, `>&` or a quote is previewed and copied first where the write runs: `echo x &> notes.md` took no copy. `npm run build &> build.log` is a file overwrite to the classifier, as `npm run build > build.log 2>&1` always was (#176).
- A line with a backslash, a caret or a backtick in it is judged again for each shell that reads it differently, and a segment with `*`, `?`, `[` or `{` in it is judged again as the shell opens it; a line with none of these is judged once, as before. `rm -rf big\data` now walks the `bigdata` bash would delete (#178, #179).

### Measured and documented

- Redirections, through the hook: of 50 spellings of a write to each of the four hook configs, 0.21.9 refuses 197 of the 200 in both modes, 0.21.10 68, and this release 200; the redirection change alone refused 197, and the three it left, spelled with a backslash in the name, are refused by the shell readings. Of 50 to `sub/.env`, 0.21.9 and 0.21.10 refuse 41 in enforce mode, and this release 50. Of 32 ordinary redirections none changes its answer, and three gain the copy they did not have.
- Moved directories: of 2,844 spellings of a write to a moved directory whose twin under the default name is refused (three directories, 73 commands, the path whole, through `~`, through `$HOME`, through the variable set and unset, both modes), 0.21.10 refuses 706 and this release 2,832. The 12 left are a directory moved away whose name is held in a variable the gate does not expand, in observe mode, and `git -C <dir> clean`, an ask: the default name does not hold those either.
- Escapes, run by the shells themselves in a copy of the project to see whether the guarded file changed: bash 5.2 ran 2,136 spellings of a write to six guarded files (the four hook configs, the gate's policy, a `.env`) with the name escaped up to five ways. Counting a line once for each mode in which its plain spelling is refused, the code before the change refused 914 of 2,634, and this release 2,634. PowerShell 7.4 ran 384, with a backtick in the name or behind a backslash; the code before refused 142 of 540, and so does this release where cmd and PowerShell are not read, as on macOS and Linux; with their readings on, as on Windows, 540. cmd is read by its documented rule.
- Opened words: bash 5.2 and zsh 5.9 ran 5,544 spellings of a write to the same six files, the directory's name written eight ways (a bracket, a negated bracket, `?`, `*`, a brace range, a brace list, a zsh group, zsh alternatives) and the file's four. Of the cells bash writes with, the code before the change refused 1,726 of 4,049, and this release 4,049; of zsh's, 2,650 of 6,064, and 6,064.
- Release by release, each of 46 binaries from v0.6.1 to v0.21.10 with its own starter: the hook config and the policy are refused under their plain names from v0.14.2, and with a backslash, a caret, `[d]`, `?`, `*` or `{e..e}` inside the name they are allowed on every release from v0.14.2 to v0.21.10, as is the hook config with zsh's `(e)`; so is the same write to a moved directory, by its path or by its variable, and from v0.15.0 a file tool's write there gets no answer. A `cd` into such a name and a write after it are asked up to v0.18.5 and allowed from v0.18.6. The redirection spellings of a write to a hook config are refused from v0.14.2 to v0.21.9 and allowed in v0.21.10 alone, where the string rule stood aside; of a write to a `.env`, allowed from v0.16.0 (`>& .env` from v0.15.0). From v0.20.0 observe mode runs the forms that are asks, `rm .clau[d]e/settings.json` and `r\m -rf /` among them, and deletes the copies under a moved state directory.
- Ordinary work answers as before each change, in both modes: the 95 everyday calls, the 304 floor lines and the 112 directory lines; 32 ordinary redirections; 92 ordinary lines with a backslash, a caret or a backtick in them, with the Windows readings on and off; and 108 with a bracket, a glob, a brace, a variable's default or `$PWD` in them (a Next.js route `app/[id]/page.tsx`, `rm -rf dist/*`, `touch src/{a,b,c}.ts`, `for f in *.md`).
- What it costs: `for i in {1..100000}` is read in about 100 ms, and the longest list measured is refused after about a second; judging `rm -rf` of a 6,000-file tree takes what it took; the plugin's hook takes a median of 2.5 to 2.9 ms a call watched, and about 1 ms standing down.
- Not read, and documented as limits: PowerShell on macOS and Linux, where a line is read as bash reads it; cmd's lack of single quotes, so that on Windows `echo 'a & copy x .claude\settings.json & rem '` is one `echo` to every reading and three commands to cmd, the second of them a write to the hook config; a name held in a variable, other than a literal default, or made by a substitution; a shell option that changes how patterns match, set anywhere but on the line itself; what lies past the budget of 20,000 directory entries and 150 ms that a segment's patterns may read. For a line no rule refuses under any reading, the preview and the copy aside are made for the line as typed. A moved directory is followed where the judging process has its variable, so under a supervisor where the supervisor has it; only the directory the variable names is followed; and a `TERMAXA_HOME` shared with other files makes all of them the gate's.
- SECURITY.md says how a line and its words are read and what is not, how a moved directory is guarded, and when a redirection's spelling and `except_reads` changed; docs/observe-mode.md says what the floor holds now; the README's limitations follow. On Windows, a backslash inside double quotes before an ordinary character (`cd "$ROOT\.claude"`), which the tokenizer drops (#50), is kept by bash's, cmd's and PowerShell's readings, and is a separator there.
- A test made state in the real `~/.termaxa`, and another test failed for it now and then on Windows; it takes a project of its own, and a test that makes state on a thread with no guard fails itself (#179). 707 tests on Linux (63 new), 601 on Windows.

### Upgrade note — a policy from before v0.22.0

`init` never rewrites a policy, and nothing here needs it to: every fix is in the reading, so a rule written for a file's name sees the spellings above, and the file in a moved directory. (A policy initialised before v0.21.3 has no path rules for the gate's own files and the hook configs: paste the five from the v0.21.4 entry's upgrade note at the top of `rules:`.) One thing changes under a policy you already have: a rule that says `except_reads` applies to a line from its first redirection on.

`termaxa check "echo x > .claud{e..e}/settings.json"` and `termaxa check "echo x > .ter\maxa/policy.yaml"` should both say `deny`.

## v0.21.10 — a path rule sees a file a command does not name, and observe mode answers nothing for an allow

**In plain words:** a path rule guards a file, and it saw that file only when a command named it. With the starter, `cp x/settings.json .claude/settings.json` is refused by a rule on the floor, because an agent's hook config is where the gate is registered. `cp x/settings.json .claude/` writes the same file and was an ask with no rule named, and so were a template copied over the project (`cp -r template/. .`) and the directory moved away (`mv .claude .claude.bak`). In a project as `init` leaves it, where the policy is an untracked directory and the hook registration an uncommitted change to a settings file git already tracks, `git stash`, `git reset --hard` and `git checkout -- .` put the settings file back as committed, without the hook, and `git clean -fd` deletes the policy: all four were asks. In observe mode, where an ask is not enforced and the floor is the one thing held, every one of these ran, and the next session started with no hook, or under another policy. The path rules now see the files a command changes inside a directory it names, and the files a git discard, a stash or a clean would undo. Apart from that, four things found while measuring observe mode on ordinary work are changed. Observe mode answered `allow` where a rule allowed the command, and Claude Code and Copilot CLI take a hook's allow as the approval, so switching the mode on skipped prompts the harness alone would have shown: it now answers nothing. It refused a native write (`Write .env`) where it observed the same write through the shell. And in both modes an append (`>>`) was read as the loss of the whole file, and reading a hook config (`grep hooks .claude/settings.json`) was refused.

Security release for [GHSA-7g97-4pmr-2vrq](https://github.com/termaxa/termaxa/security/advisories/GHSA-7g97-4pmr-2vrq) (High), found on Nov 14, 2026 while reading the code for #171, the git commands the same day by measuring the first fix on a project as `init` leaves it, and measured on each release's own starter back to v0.6.1. One of the git commands had been seen before: in Max Petrusenko's field report of Oct 9, 2026 a `git clean -fdx` removed an untracked `.termaxa/policy.yaml`. v0.21.3 answered by making a delete of `.termaxa` a floor rule and left `git clean` itself unread; it is read now. Two code PRs: #172 is the fix, #171 the four changes above. The advisory lists when each form started.

### Security

- A file copied or moved into a directory is a target under its own name there, read off the command: `cp`, `mv`, cmd's `copy` and `move`, `git mv`, PowerShell's `Copy-Item` and `Move-Item` by their own parameters, `Rename-Item` and `ren`. A glob is what it matches on disk, a brace list is opened, `-t` and `-T` are honoured, and a destination the gate cannot look at is read as a directory. `cp x/settings.json .claude/` is a deny by `path:*/.claude/settings*.json`, on the floor, as the named spelling is (#172).
- A tree is read off the disk: what `cp -r` or `mv` lands, and what a delete or a move takes with a directory, where it lands on or lies in the project or an agent's configuration under the home directory. The walk goes breadth first and dot-names first, under the delete preview's budget of 5,000 files and 300 ms of walking; a directory a build rebuilds and `.git` are not entered. `rm -rf .claude` was a deny by `*rm -rf*`, which is not on the floor, and `rm -r .claude` an ask: both are a deny by the path rule now, held in observe mode (#172).
- A checkout of its own inside the project, a worktree under `.claude/worktrees` or a clone in `vendor/`, is not entered either: its hook config is that checkout's, and `rm -rf` of it is judged as before. The project itself, or a directory above it, goes with everything in it and is judged as before (#172).
- Git is asked what it would do, in the directory the command runs in. A discard (`reset --hard`, `checkout [--] <paths>`, `restore <paths>`, `checkout -f`, `switch --discard-changes`) puts back as committed the files `git status` reports; a clean that is not a dry run removes what `git clean -n` lists, a command rebuilt from an allowlist and never passed through; a stash takes both kinds. Each file is a target for the path rules, with its role in the reason: "put back as committed", "removed", "taken into a stash". When the directory cannot be read (`cd "$(git rev-parse --show-toplevel)" && git stash`), a command that names no path is read in the project's own repository (#172).
- A stash keeps what it takes, so only a rule on the floor is asked about a stashed file: `git stash` with local edits in a tracked `.env` is judged as before. A discard and a clean are losses, and every path rule is asked: in enforce mode `git reset --hard` over those edits is a deny by the `.env` rule, and so is `git clean -fdx` over an ignored `.env` (#172).
- Only the path rules read these targets. The preview, the copy aside and the classifier see the command as they did (#172).

### Changed

- Day one costs a commit. Until `.termaxa/policy.yaml` and the hook config are committed, a `git stash`, `git reset --hard`, `git checkout -- .` or `git clean -fd` that would put them back or delete them is refused in both modes, with the file named in the reason: all four where git already tracked the settings file, `git clean` and `git stash -u` where `init` created it. `init` now ends by saying so, and by saying to commit them or to keep a new hook config out of git's way in `.git/info/exclude`. Once they are committed those commands are judged as before (#172).
- `git checkout -f` (or `--force`) and `git switch --discard-changes` (or `-f`, `--force`) are read as the discards they are: the preview lists the uncommitted changes that would be lost and the stash snapshot is taken first, as for `git reset --hard` (#172).
- Observe mode answers nothing for an allow, in every harness, for a shell command and for a native write. Until now it said `allow` wherever a rule allowed the command; Claude Code takes a hook's `allow` as the approval and skips its own prompt, and so does Copilot CLI. The record is what it was (`decision allow`, `mode observe`, `enforced true`), `doctor`'s probe still reads the policy's verdict, and the floor still answers. What it costs: a run that leaned on that answer, an unattended session that must prompt for nothing, gets its approvals from the harness's own settings, or from enforce mode, where an allow is an allow (#171).
- Observe mode observes a native write. A path rule's deny on `Write` or `Edit` was enforced in observe mode and its record line carried none of the mode's fields: `Write .env` was refused where the shell's `echo KEY=2 > .env` ran after its copy. Now a floor rule holds, and so does a delete of a tree past the copy budget; any other ask or deny is recorded with `mode`, `enforced: false` and its coverage, the file copied aside first, and nothing is said to the harness. The gate's own files and the hook configs are refused as before. In enforce mode a native write is answered as it was (#171).
- An append is not a loss. `>>` and `tee -a` add to a file and what it held stays; the preview read the line as an overwrite of the whole file with no way back, and that turned an ask into a refusal: `curl -s http://localhost:3000/health >> notes.md` was refused in both modes. A target that every write on the line only adds to is previewed as losing nothing (`echo a >> f; echo b > f` is still an overwrite). A path rule still judges the write: an append to `.env` is refused in enforce mode and observed in observe mode, and an append to `.claude/settings.json` is held in both (#171).
- A deny can say `except_reads: true`: it then does not apply to a command that cannot write a file, one of 22 programs that only read or print (`cat`, `head`, `tail`, `wc`, `grep`, `stat`, `ls`, `diff`, `jq`, `echo` and their kind), or `git` followed at once by `diff`, `show`, `log`, `status`, `blame`, `ls-files`, `add` or `commit`, named plainly as the line's first word. What such a command writes through a redirect is a target, and the path rules judge it first; a wrapper in front, a program named by a path and `git -c ...` meet the rule as written. The starter's four string rules over the hook configs say it, so `grep -n hooks .claude/settings.json` and `git commit -m "update .claude settings"` are no longer refused; the rules over the gate's own files do not, and reads of those stay refused but for the ones the starter lists. The starter still has 229 rules (#171).

### Measured and documented

- Through the hook, 0.21.9 against this release, each with its own starter, in a project as `init` leaves it, one that tracked `.claude/settings.json` before. Of 57 ways to copy, move, rename or delete a guarded file without naming it (with `cp`, `mv`, `rm`, `git mv`, `git rm`, their PowerShell names, and `install`, `rsync`, `ln`, `tar`, `unzip` and `find`), 0.21.9 refused 13 in enforce mode and asked about 44, and observe mode held 6; this release refuses 49 and holds 47. The ten that still run in observe mode: a copy of a `.env`, refused in enforce mode by a rule that is not on the floor; a glob that matches no dot-directory (`cp -r tpl/* .`); `rm -rf ~` with a small home outside the project; and seven that are not read (`install`, `rsync` twice, `ln -sf`, `find -exec cp`, `tar -xf`, `unzip`).
- Of 18 git commands that would undo the hook config or the policy, 17 were asks on 0.21.9 and ran in observe mode; 16 are refused here in both modes, and the two that are not are a clean that excludes the guarded directories and one run in `src/`. With the policy and the hook configs committed, 14 of the 16 are asks again: `git checkout -- .claude/settings.json` is refused as it always was, for the name, and `git clean -fdx` in enforce mode, for the ignored `.env` it would delete. Nine git commands that undo nothing (`stash list`, `stash pop`, `clean -n`, a discard of `src/`), five deletes, moves and copies of a nested checkout, and 21 ordinary copies, moves and deletes are judged as on 0.21.9.
- The 95 calls of an ordinary Claude Code session. Enforce mode on 0.21.9: 29 allow, 34 ask, 24 refused, 8 no answer. Here, with the policy and the hook configs committed: 31, 34, 22, 8, the two reads of a hook config. In the state `init` leaves: 31, 31, 25, 8, where `git stash`, `git reset --hard HEAD` and `git clean -fd` move from an ask to a refusal. Observe mode on 0.21.9: 29 allow, 19 refused, 47 no answer. Here: no allow, 15 refused, 80 no answer, and 18 and 77 before the commit. The 29 allows are not answered, and four refusals are observed: the two reads, `echo "KEY=2" >> .env` and `Write .env`. The 15 are the floor: four native writes to the gate's own files and the hook configs, `rm -rf bigdata` (6,000 files, past the copy budget), and ten commands the floor holds.
- The floor matrix of v0.21.9 (38 rules, seven spellings) is 266 of 266 refused in both modes, on 0.21.9 and here.
- Each release's own binary with its own starter, v0.6.1 to v0.21.9, 45 of them: through v0.14.1 the named copy is itself an ask, because nothing guarded the hook config; from v0.14.2 the named copy is refused and the directory and git spellings are asks; from v0.16.0 `cp x/.env .` is an ask beside a refused `cp x/.env .env`; and from v0.20.0 observe mode runs them.
- What the reading costs, on Linux, on a static musl build of this tree, which is how the release asset is built, against the released 0.21.9; medians of eleven to fifteen calls through the hook, spawning included. An ordinary line is unchanged, and the median of the 95 calls is 3.2 to 3.5 ms on both. `git stash` takes 7 ms (3.5 on 0.21.9), two questions to git; `git reset --hard`, once the policy is committed, 22 ms (18); `git clean -fdx` about 20 ms (5) where the ignored bulk is a build directory, which is not entered, and 85 to 120 ms over an ignored tree of 6,000 files, which is read up to the budget. Such a tree copied, moved or deleted inside the project costs about 100 ms (4 ms, and 12 ms for the delete, which the preview already counted). The longest lines measured for v0.21.9 cost what they did, or up to a fifth more (a 100 KB word eight substitutions deep: about 3.2 s, where 0.21.9 takes 2.6 to 2.8 s).
- Not read, and documented as limits: `install`, `rsync`, `ln`, `find -exec`, an archive unpacked over the project, a name held in a variable, a tree past the budget, a git alias, a git command given `--git-dir` or `--work-tree`, and what git brings in from another commit (a branch switch, a merge, a pull, a rebase, a revert, `reset --hard <commit>`, `checkout <commit> -- <paths>`, `stash pop`), which is read only for the uncommitted changes it discards on the way. The preview and the copy aside do not read the new targets: in observe mode `cp x/.env .` runs with no copy of the `.env` it overwrites, recorded `known-uninsured`, and `git stash` and `git clean` have no preview and no copy.
- SECURITY.md says what a path rule reads of a command that does not name its file and what it does not; docs/observe-mode.md says what the mode answers, how it treats a native write and what the floor holds of the gate's own files; the README's quick start, modes, policy and limitations sections follow. docs/found-in-the-wild.md gains the field report's `git clean`, 51 now. A dated correction under v0.21.9: its timing figures were a local build's.
- 644 tests on Linux (19 new), 550 on Windows.

### Upgrade note — a policy from before v0.21.10

`init` never rewrites a policy. The security fix is in the reading and needs nothing from the policy: a path rule written `*/.claude/settings*.json` sees the copy into the directory and the git discard as it stands. (A policy initialised before v0.21.3 has no path rules for these files: paste the five from the v0.21.4 entry's upgrade note at the top of `rules:`.) Three things change under a policy you already have:

- If the policy and the hook config are not committed yet, a `git stash`, `git reset --hard`, `git checkout -- .` or `git clean` that would undo them is refused in that project until they are. `git add .termaxa/policy.yaml .claude/settings.json` and a commit end it; a hook config kept to one clone can go in `.git/info/exclude` instead.
- In observe mode an allow is no longer answered. A run that leaned on the hook's `allow` to skip the harness's own prompt sees that prompt again: grant it in the harness's permission settings, or use enforce mode.
- In observe mode a native write denied by a rule that is not on the floor (`Write .env`) is observed: recorded, copied aside first, and run.

Reading a hook config is the policy's to allow, so an existing policy refuses `grep -n hooks .claude/settings.json` as before until the line is added to its four string rules over the hook configs (`*.claude*settings*`, `*.cursor*hooks*`, `*.codex*hooks*`, `*.github*hooks*`):

```yaml
  - match: "*.claude*settings*"
    action: deny
    reason: "Agent hook configuration is off limits — editing it unhooks the gate."
    floor: true
    except_reads: true
```

`termaxa check "grep -n hooks .claude/settings.json"` should then say `allow`, and `termaxa check "sed -i s/a/b/ .claude/settings.json"` should say `deny`.

## v0.21.9 — a substitution hides no command, and enforce mode lets a build directory go

**In plain words:** the shell runs a command out of another command's words, `cat <(...)` or `echo $(...)`, and the gate read that command as part of the words around it, or not at all. With the starter, `cat <(kubectl delete pod web-1)` was allowed by `cat *`, though `kubectl delete*` is a hard stop, and `cat <(git push origin main)` ran without the ask a push gets. A hard stop behind `timeout 60`, in a `{ ...; }` group or in a function's body was asked about where it should be denied. In observe mode, where an ask is not enforced and the floor is the one thing held, all of these ran, and so did a floor command that followed an ordinary deny on the same line (`rm -rf dist; kubectl delete ns prod`). A command is now read where the shell runs it: the first command of a substitution is a command, a deny rule finds its command behind `timeout` and its kind, the floor's deny is the line's verdict wherever it sits on the line, and a line nested deeper than the gate reads is refused. Apart from that, enforce mode now lets a build directory go, as observe mode has since v0.21.3: under the new starter `rm -rf node_modules` and `rm -rf dist` are no longer refused.

Security release for [GHSA-84qh-xh6v-3qhr](https://github.com/termaxa/termaxa/security/advisories/GHSA-84qh-xh6v-3qhr) (High), found on Nov 13, 2026 while measuring observe mode's floor before building on it, and measured on each release's own starter back to v0.6.1. Three code PRs (#166, #167, #168). The advisory lists when each form started.

### Security

- Between two denies on one line, the one on the floor is the line's verdict, and the reason names its segment. A line's verdict carries one rule, and observe mode holds a line only when that rule is on the floor, so `rm -rf dist; kubectl delete ns prod` was a deny by `*rm -rf*` and ran in observe mode, `dist` copied aside (#166).
- The first command of a `$( ... )`, a backtick substitution, a `<( ... )` or a `>( ... )` is a segment of its own, read through any wrapper in it, where it runs: it is previewed, insured and classified like any other, and a `cd` that opens a substitution moves the rest of it and nothing after it, so `x=$(cd .termaxa; echo "default: allow" > policy.yaml)` is a write to the gate's policy. A deny on such a segment denies the line. A quoted heredoc (`git commit -m "$(cat <<'EOF' ... EOF)"`) is data, as before (#166).
- A command read this way that no rule allows makes an allowed line an ask, with the command named in the reason: the rule a `$( ... )` has had since v0.19.3, now for a process substitution, which was read for nothing, and for a substitution beside a wrapper's string (`sh -c "ls" $(git push origin main)`), which was lost with the wrapper (#168).
- Substitutions are read eight levels deep and a hundred to a line; a `-c` string four deep, as before. A line that goes past one of these is refused in every mode, observe included, with no rule named: nothing read the command left over, so nothing can say the floor is not in it. Until now the reading stopped at four levels without a word, and five deep a hard stop was judged by the command around it (#168).
- Every deny rule, the classifier, the preview and the copy aside find the command past `timeout` (which owns its duration), `time`, `exec`, `setsid`, `stdbuf`, `watch`, `!`, `{` and a function's header. An allow rule reads through `timeout` only: `timeout 60 npm test` is allowed by `npm test*`, and `time npm test` asks as before (#166).

### Changed

- Enforce mode lets a build directory go. A deny can say `except_rebuilt: true`: it then does not apply to a delete whose every target is, or sits inside, one of the eighteen directories a build or an install rebuilds (`node_modules`, `.next`, `dist`, `build`, `target`, `.venv` and their kind), inside the project root. With no other rule naming the command it is allowed, by the gate and by no rule, the copy aside taken first when the directory is under the budget, and the harness's own prompt is what it was. With any other target on the command (`rm -rf node_modules src`), a link, a variable or a target outside the project, the rule applies as written. The starter's seven recursive-delete denies carry the field; it still has 229 rules (#167).
- Two such deletes in a session are no longer two attempts to the circuit breaker, so the delete after them that would only have asked (`rm -r src/old`) asks, where 0.21.8 refused it until a recorded resume (#167).
- `diff <(sort a.txt) <(sort b.txt)` asks, where it was allowed by `diff *`: `sort` has no rule, because `sort -o` writes a file with no redirect for the gate to see, and it asks typed plain. `diff <(git show HEAD:a) <(cat a)` is the allow it was (#168).

### Measured and documented

- Through the hook with the starter, 0.21.8 against this release. Each of the 38 floor rules by a command that names it, in seven spellings (plain, behind `rm -rf dist;`, in `x=$( )`, behind `timeout 60`, two substitutions deep, in `{ ; }`, in a function's body), 266 lines: observe mode held 191 and holds 266; enforce mode denied 236, asked about 25 and allowed 5, and denies 266. In seven deeper spellings (five to twelve substitutions deep, and beside a wrapper's string), 266 lines: enforce mode denied 224, asked about 6 and allowed 36, and denies 266; observe mode held 210 and holds 266.
- Fifteen commands the starter asks about (its fourteen ask rules and one command with no rule) in ten spellings, 150 lines in enforce mode: 0.21.8 asked about 32 and allowed 118; this release asks about 135, refuses the 15 that are nine deep and allows none.
- Ninety-one ways to run `kubectl delete pod web-1`: 0.21.8 denied 35, asked about 52 (which ran in observe mode) and allowed 4; this release denies 55, asks about 36 and allows none. The 36 are what is still not read: a runner the gate does not know (`strace`, `flock`, `ionice`, `chroot`, `docker exec`, `ssh` and their kind), a pipe into a shell, `coproc`, `trap`, an alias, a command named by a variable set elsewhere or by a substitution, an interpreter's inline code, a script. In enforce mode they ask; in observe mode they run. SECURITY.md and docs/observe-mode.md say so.
- Ordinary work, each release with its own starter. Of the 95 calls of an ordinary Claude Code session, four verdicts move in enforce mode: `timeout 60 npm test` from an ask to an allow, `rm -rf dist` and `rm -rf node_modules` from refused to no answer, and the two together followed by `npm install` from refused to an ask on the install. In observe mode the hook's answer moves on one, the `timeout` line. Of 51 ordinary lines with a substitution in them, three move: `timeout 60 git log $(git describe --tags --abbrev=0)..HEAD --oneline` from an ask to an allow, and the two `diff <( ) <( )` lines over `sort` and `jq` from an allow to an ask.
- The limit of a hundred substitutions to a line is there for time: each command read is judged by every rule, and a 118 KB line of 6,561 substitutions nested eight deep took the hook 9.8 s before the limit (0.34 s on 0.21.8); it is refused in 0.26 s.
- The conformance test against bash still holds on 1,500 generated command lines per run.
- SECURITY.md says how a substitution and a runner are read and what is still not read; docs/observe-mode.md says what the floor reads on a line; the README's modes, policy and limitations sections follow. A dated correction under v0.21.8: with the eleven project rules the record measures 59 allow, 63 ask, 1 deny.
- 625 tests on Linux (23 new), 535 on Windows.

### Upgrade note — a policy from before v0.21.9

`init` never rewrites a policy. The security fixes are in the reading and need nothing from the policy: a hard stop written `kubectl delete*` is found inside a substitution and behind `timeout` as it stands, and the floor is whichever rules already say `floor: true`. Letting a build directory go in enforce mode is the policy's to say, so an existing policy denies `rm -rf node_modules` as before until the line is added to its recursive-delete denies (`*rm -rf*`, `*rm -fr*`, `*Remove-Item*-Recurse*`, `*Remove-Item*-Force*`, `*del /s*`, `*rmdir /s*`, `*rd /s*`):

```yaml
  - match: "*rm -rf*"
    action: deny
    reason: "Recursive force delete blocked by default policy."
    except_rebuilt: true
```

`termaxa check "rm -rf node_modules"` should then say `allow`, and `termaxa check "rm -rf src"` should say `deny`.

### Correction, Nov 14, 2026

The entry above says a 118 KB line of 6,561 substitutions took the hook 9.8 s before the limit (0.34 s on 0.21.8) and is refused in 0.26 s. The 9.8 s and the 0.26 s were measured on a local build linked against glibc, the 0.34 s on the released 0.21.8, which is a static musl build and slower. On the two released binaries, measured again on Nov 14, 2026, 0.21.9 refuses that line in 0.4 to 0.5 s, about what 0.21.8 takes to allow it. And the limit does not make every long line fast: a 100 KB word eight substitutions deep, which is under it, takes the released 0.21.9 2.6 to 2.8 s where 0.21.8 took 0.2 s, and 12,000 `sh -c "ls"` on one line take 4 to 5 s on both.

## v0.21.8 — a line of a file is not a command, and the demo runs on a project the gate can see

**In plain words:** an agent that writes a file through a heredoc and builds, tests or commits in the same call was asked about the first line of the file that matched no rule, and once refused on a JavaScript line for looking like a path. The file's contents are now data: a hard stop spelled in them still denies, nothing else in them is a verdict, and the build or the commit after them is what gets judged. `termaxa demo` had been denying its own three checks since v0.21.3, because its scratch project sat under `~/.termaxa`, which the floor protects; it now builds in the temp directory. Five heads an unattended agent ran this week join the starter as allows.

Measured on the SynCircles record: an agent (Claude Code, headless) building a real Next.js and Supabase product under the gate in observe mode, Oct 26 to Nov 5, 2026, 123 hook verdicts, every command replayed through `check` on each release. Two code PRs (#163, #164).

### Changed

- A line of a literal heredoc's body that the shell never runs, the contents of a file written by `cat` or `tee` or the program of an interpreter (`python3 -`, `node -`, `psql`), is matched against deny rules and nothing else, even when the rest of the line keeps the body read because it could run the file (`git commit`, `npm run build`, `supabase db push`, a `$(…)`). A hard stop in it denies, as before; a line that matches no rule is data, never the policy default; no target in it is resolved, previewed, insured, classified or read for context signals (`delete from` in a migration's text no longer escalates the write). A body a shell runs (`bash <<'EOF'`), an unquoted body, and a body written where it runs on its own (a git hook, `profile.d`) are commands, as before (#163).
- The delimiter line that ends a heredoc is never a segment: the shell reads it only to end the body, and a line that kept its bodies read asked on `EOF` (#163).
- `termaxa demo` builds its scratch project at `<temp dir>/termaxa-demo-<ts>`. Under `~/.termaxa/demo/project-<ts>`, where it sat since the demo shipped, the floor's path rule on the gate's own files (`*/.termaxa/*`, v0.21.3) denied all three checks with "Termaxa's own config is off limits", where the narration promised a counted blast radius, a `.env` rule and an ask with insurance planned. Its test now runs with a state directory named `.termaxa`, as a user's is, which is how the test had missed it (#164).
- Starter: `mkdir *`, `ps`, `ps *`, `sleep *` and `tee *` are allows; 229 rules, 162 of them allows, 38 on the floor. `tee`'s file is judged by the path rules and copied first, as a redirect's target is (#164).

### Measured and documented

- On the record's 123 verdicts, with the repository's own policy (0.21.6's starter, observe mode): the hook's verdicts were 34 allow, 88 ask, 1 deny (a `drop table` the agent wrote by hand for a planted stray table, not on the floor, so it ran). `check` on the released 0.21.6 returns the same 123. On 0.21.7: 36 allow, 85 ask, 2 deny: two heredoc writes became allows, the only two with nothing else on the line, since 36 of the 38 were on a line that also built, tested or committed and that reading kept their bodies read; and one ask became a deny, the template literal (#163's commit message gives 0.21.7 the 0.21.6 figures; these are the measured ones). On this release: 36 allow, 86 ask, 1 deny, every remaining ask on a command, none on a line of a file. With eleven project rules for the project's own loop (`npm run build|smoke|lint`, `npm ci`, `npx eslint`, `mkdir`, `ps`, `supabase migration new|list`, `supabase db push --db-url`, `git revert`): 58 allow, 64 ask, 1 deny. What still asks is the Supabase CLI's `db query`, `python3 -` edits, `git push`, `timeout N <cmd>` (not stepped over as `env` is; next), `sed` reads of `.env.local`, `kill` and `pkill`, `curl` to localhost.
- The two reading changes do not move the conformance test against bash, which still holds on 1,500 generated command lines per run.
- SECURITY.md says which heredoc bodies are data and which are commands. docs/found-in-the-wild.md gains the two findings from the record, 50 now.
- The doctor test's `init` runs on the same controlled PATH as its `doctor`; on a box with `claude` installed it had wired a hook the test could not see.
- 602 tests on Linux (three new), 516 on Windows.

### Docs

- README.ja.md, a Japanese translation of the README as of v0.21.7, by Lesstep (#162), reviewed line by line against the English before merge; the English is authoritative and the translation says so.

### Correction, Nov 13, 2026

The entry above says that with the eleven project rules the record measures 58 allow, 64 ask, 1 deny. The released binary gives 59 allow, 63 ask, 1 deny: replayed twice on Nov 11, 2026 in a fresh state directory, the same per command as the Nov 5 run's own record. The figures without the rules (36 / 86 / 1) and the hook's own verdicts (34 / 88 / 1) reproduce.

## v0.21.7 — a comment hides no command, and a file written through a heredoc is judged by its path

**In plain words:** the shell reads neither a `#` comment nor a heredoc's body as syntax, but the gate did: a quote in either (`# it's clean`, a body line `echo it's`) opened a string that carried the lines after it into the same segment, where the first line's verdict covered them. With the starter, `git status # it's clean` above `kubectl delete namespace staging` was allowed by `git status*`, though `kubectl delete*` is a hard stop. Comments and heredoc bodies are now read the way the shell reads them. And a file written with `cat > file <<'EOF'`, which is how agents write files through the shell, was read a line at a time as commands: on the first SynCircles run (Oct 25, 2026) that was the largest class of asks on real work, about 8 of 26. A literal heredoc that `cat` or `tee` writes to a file is now judged as the write it is, by its path, as a write through the Write tool is.

Security release for [GHSA-rp8h-f4h4-w4j3](https://github.com/termaxa/termaxa/security/advisories/GHSA-rp8h-f4h4-w4j3) (High), found on Oct 27, 2026 while reviewing the heredoc change, and measured on each release's own starter back to v0.7.0. Two code PRs (#158, #159). The advisory lists when each form started.

### Security

- A `#` that starts a word opens a comment that runs to the end of its line, and inside it a quote or a backslash is literal; a `<<` in it opens no heredoc. `a#b`, `$#`, `${#x}`, `"#"`, `\#` and `a\ #b` hold no comment, as in bash. The split still divides a comment at operators and keeps its text for rule matching, because cmd.exe has no comments and the hook receives its commands too: a comment that mentions `rm -rf` still denies. A comment alone on its line runs nothing, and its segment is transparent the way a `do` or a `fi` is (#158).
- A heredoc's body is read up to its delimiter line as the shell finds it: the word after `<<` ends at the first metacharacter, the delimiter is what the shell's quote removal leaves, the line must equal it (with leading tabs stripped under `<<-`), and each body line is read on its own, so nothing in it reaches the lines after (#158).
- A test runs the split against bash on generated command lines, 1,500 on every run, and fails if a command bash runs is not a segment here (#158).

### Changed

- A literal heredoc (a quoted delimiter, so the shell expands nothing in it) that plain `cat` or `tee` writes to a file is the file's contents, and the segment is judged as the write: by its path, with the copy aside. It stays data only where nothing can run it. The owner is not piped or sent to the background and writes no descriptor's path and no file that runs on its own (a shell's startup file, a git hook, git's config); every other command on the line is one that cannot run the file or change what wrote it, from a short hand-walked list (`cd`, `mkdir`, `ls`, `echo`, `cat`, `tee`, `rm`, `chmod`, `test`, `set` with options, git's `add`, `status`, `diff`, `log` and a few more); and the shell ends the body where a looser reading would too. Anything else on the line keeps every body on it read as before (#159).
- The trade, as decided on Oct 27: a body that spells a hard stop no longer denies the write of an ordinary file on a quiet line. `cat > cleanup.sh <<'EOF'` / `rm -rf ~` / `EOF` is a write, and running the file later is judged as running any script is, the same as for a file the Write tool wrote. v0.19.3's rule that a heredoc body spelling a hard stop still trips it now holds for unquoted heredocs, for a line that also builds or runs, and for anything piped (#159).

### Measured and documented

- With `termaxa check` and the starter against the released 0.21.6: `git status # it's clean` above `kubectl delete namespace staging`, the same comment above `terraform destroy -auto-approve` or `docker system prune -af`, and `cat <<EOF` / `echo it's` / `EOF` above it go from allow to deny; a comment holding a quote above `git push --force`, `kubectl delete`, `terraform destroy`, `dd` to a device or `mkfs` goes from ask to deny; `# list the files` above `ls -la` from ask to allow (#158).
- A Next.js page written through a heredoc goes from ask to allow; a note that mentions `rm -rf`, from deny to allow; `cat >> .gitignore`, a write then `git add`, and `cd src && cat > ...`, from ask to allow; the same page written through `bash -lc` and through Claude Code's `eval` wrapping, from ask to allow. `.env`, `.claude/settings.json`, a command after the body, `bash <<'EOF'`, `| sh`, an unquoted `$(rm -rf ~)`, `~/.bashrc`, a git hook and a script written and run on one line deny as before, and all 78 heredoc shapes from the reviews keep their 0.21.6 deny or ask (#159).
- SECURITY.md says a literal heredoc written to a file is judged by its path, and that comments and heredoc bodies are read as the shell reads them. The README states the advisory policy instead of a count, and RELEASING.md's security step matches.
- 599 tests on Linux (ten new), 513 on Windows.

## v0.21.6 — a path read only at its end is judged by its end

**In plain words:** a `cd` whose argument the gate could read only part of, `cd "$(git rev-parse --show-toplevel)/.claude"`, `cd "$ROOT/.claude"` or `cd .cla*`, left the directory unknown as a whole, so a write after it was unresolved and the starter's `echo *` outranked that: `… && echo {} > settings.json` was allowed from v0.18.6 (the substitution spelling from v0.19.3), while `cd .claude && echo {} > settings.json` has been a floor deny since v0.21.4 and the direct spelling since v0.14.2. The same held for a target that starts with a variable: `cat .env.example > $PWD/.env` was allowed from v0.15.0, the release that first denied `> .env`. The end of such a path is literal, and the path rules now read it: wherever the start is, that write lands on a `.claude/settings.json`, or a `.env`.

Security release for [GHSA-4mqm-4c42-2xxc](https://github.com/termaxa/termaxa/security/advisories/GHSA-4mqm-4c42-2xxc) (High), found on Oct 14, 2026 while checking GHSA-3hg6-x893-mfr4's list of unreadable `cd`s and measured on the released 0.21.4 and 0.21.5. Two code PRs (#154, #155). The advisory lists, release by release, when each form started.

### Security

- A path the gate can read only the end of is judged by its end. After `cd "$(git rev-parse --show-toplevel)/.claude"` the shell is somewhere ending in `.claude`, a relative target there ends in `.claude/<target>`, and a `match_path` rule whose first component is `*`, matching at any depth, names that end with certainty, because the `*` consumes whatever the start is; a rule anchored at the root (`/etc/*`) cannot be sure and does not match. The floor rules on `.termaxa/`, `.claude/settings*.json`, `.cursor/hooks.json`, `.codex/hooks.json` and `.github/hooks/*` fire on these spellings in both modes, `*/.env` in enforce mode. The preview and the copy aside still treat the directory as unknown; only the verdict changes (#154).
- A `cd` from a directory nothing is known of ends in its own path: `cd "$X" && cd .claude && echo {} > settings.json` is denied (#154).
- A target that starts with a variable ends in what follows it: `cat .env.example > $PWD/.env`, `echo KEY=1 >> "${ROOT}/.env"` and `echo {} > %USERPROFILE%\.claude\settings.json` are denied. `echo x > "$X/policy.yaml"` ends in a name no rule has and stays allowed, as SECURITY.md says (#154).
- A glob in a `cd` is expanded against the directory it runs in, as the delete preview expands a target's since v0.21.2, and counts when exactly one directory matches: `cd .cla* && echo {} > settings.json` is denied, and `cd .cla* && rm -r data` is previewed and copied where it runs. A glob the gate cannot expand (`cd wt*/.claude`, two matches, none) still ends in what follows it (#154, #155).
- An unquoted `$(git rev-parse --show-toplevel)/.claude` was three words to the tokenizer and is read as the one word it is to the shell, for `cd` (#154).

### Measured and documented

- Each release's own starter, through the hook: the `.env` spelling allowed from v0.15.0; the variable, glob and relative-after-unknown `cd` spellings from v0.18.6; the substitution spelling from v0.19.3; all denied here. The advisory carries the table.
- On one list of 31 `cd` spellings against 0.21.5: 17 go from allow to deny by the path rule, `pushd …` and `tee policy.yaml` from ask to deny; the reads after a `cd` and the documented limits keep their verdicts.
- Two reviews ran on the change, as on #148. The code review found the glob case #155 fixes, and that after `;` a move into such a directory is taken as made: the gate cannot check it exists, so a `cd` that failed costs a deny the write did not need, never an allow. The adversarial pass, 165 spellings, found no `cd` spelling an agent would write that passes and no wrong deny from the end-matching; it found the `.env` variable case, fixed in #154, and that the starter's string rules over-match ordinary work (`git commit -m "update .claude settings"` and `grep hook .claude/settings.json` deny), which predates this release and is on the roadmap.
- Still the documented limit: a `cd` nothing can be read of (`cd "$X"`, `cd "$(cd .claude && pwd)"`) followed by a relative write whose own path names no rule, and, on Windows, `cd "$ROOT\.claude"` with the backslash inside double quotes, which the tokenizer reads as `$ROOT.claude` (#50's documented divergence; the two lexers move together, next). SECURITY.md's list of unreadable `cd`s says so.
- The README's count of bugs found in the wild reads 48, the list's length since #153.
- 589 tests on Linux (six new), 508 on Windows.

### Upgrade note — a policy from before v0.21.3

As for v0.21.4: a policy initialised before v0.21.3 guards these files with string rules, which see one segment at a time, so with that policy this release changes nothing for the `cd` spellings. Paste the five path rules from the v0.21.4 entry's upgrade note at the top of `rules:`.

## v0.21.5 — the Windows exe carries its runtime

**In plain words:** every Windows build of Termaxa so far needed the Visual C++ 2015+ redistributable to start. Most developer machines have it; a clean Windows does not, and there `termaxa.exe` exited at once with `0xC0000135` (STATUS_DLL_NOT_FOUND), before any policy was read. A hook that cannot start fails open: the harness treats the error as non-blocking and runs the command anyway. winget's validation of 0.21.4 found it on Oct 17, 2026 ([microsoft/winget-pkgs#452044](https://github.com/microsoft/winget-pkgs/pull/452044)). The exe now links the C runtime statically and depends on nothing but Windows.

### Fixed

- The Windows asset no longer imports `VCRUNTIME140.dll` or the `api-ms-win-crt-*` sets. `.cargo/config.toml` sets `target-feature=+crt-static` for `x86_64-pc-windows-msvc`, so the release build, CI and a local build all link the same way; the imports left are `kernel32`, `ntdll`, `api-ms-win-core-synch-l1-2-0`, `bcryptprimitives`, `bcrypt`, `ADVAPI32` and `WS2_32`, all part of Windows. The 0.20.1, 0.21.3 and 0.21.4 assets all carried the dependency; until a machine without the redistributable upgrades, `winget install Microsoft.VCRedist.2015+.x64` makes those start (#151).

### Measured and documented

- `dumpbin /dependents` on the release build, a byte search of the exe for both names, and the Windows gate: 502 passed, 0 failed, every test binary linked statically too. A run on a Windows without the redistributable was not possible on the build machine; winget's validation of this release runs the exe on one, and its result is the end-to-end check.
- Nothing else changed: 583 tests on Linux, the starter policy as in v0.21.3.

## v0.21.4 — a path after a cd is where the cd went

**In plain words:** a write or delete spelled after a `cd` was judged as if the `cd` had not run. `cd .claude && echo {} > settings.json` matched no path rule, and the starter allowed it from v0.18.6 on, while `echo {} > .claude/settings.json` is a floor deny; the gate's own policy, `.cursor/hooks.json`, `.codex/hooks.json` and any rule of yours that names a directory were sidestepped the same way. The preview and the copy aside had the same blind spot, which is how the lead item of Max Petrusenko's field report found it: from a main checkout, `cd ../wt && rm -r data` was previewed as "does not exist" and, in observe mode, ran with nothing copied. Every part of a command line is now judged in the directory it runs in.

Security release for [GHSA-3hg6-x893-mfr4](https://github.com/termaxa/termaxa/security/advisories/GHSA-3hg6-x893-mfr4) (High), found on Oct 12, 2026 while fixing that item. One code PR (#148). The advisory lists, release by release, when each form started.

### Security

- A path after a `cd` is judged where the `cd` went. `cd`, `chdir`, `pushd`, `Set-Location`, `sl` and `Push-Location`, also behind `builtin`, `command`, `time`, an assignment, a backslash or a brace, carry over `&&`, `;` and newlines, and not over `|` or `&`; a `( ... )` subshell restores the directory when it closes; a `cd` inside `eval` carries on after it, and one inside `sh -c` does not. The path rules on `.termaxa/` and the hook configs fire on the file the shell will touch: `cd .termaxa && echo x > policy.yaml`, `cd .claude && echo {} > settings.json`, `cd .cursor && echo {} > hooks.json` and `cd .codex && echo {} > hooks.json` were allowed and are denied, in both modes, and `cd .termaxa && rm policy.yaml` was an ask and is denied (#148).
- A `cd` the gate cannot read (`cd "$X"`, `cd -`, `popd`, one under `if` or after `||`) leaves the directory unknown. A relative path after it is unresolved: refused like a variable in a path, and previewed as an unresolved directory rather than guessed (#148).

### Fixed

- The preview, the copy aside and the pre-execution re-check read the directory a segment runs in, and git's `-C`. `cd ../wt && rm -r data` and `git -C ../wt rm -r data` count and copy `../wt/data`; `cd ../wt && git reset --hard` snapshots the uncommitted changes in `../wt`; a force-push pin and a terraform plan run in the segment's directory; rolling back a pin pushes from the repository it was taken in (#148, from Max Petrusenko's field report, Oct 9).
- A subshell's parentheses are not part of a file name: `(cd .claude && echo {} > settings.json)` writes `settings.json`, not `settings.json)` (#148).

### Measured and documented

- Every release from v0.14.2, through the hook against its own starter policy: the advisory has the release in which each `cd` spelling became an ask or an allow.
- 46 ordinary commands (`cd src && cargo test`, `git -C sub status`, Claude Code's `bash -c -l "... eval '...'"` wrapper and more) keep their v0.21.3 verdicts.
- SECURITY.md says what a `cd` the gate cannot follow does, and that an explicit allow still outranks an unresolved target: `cd .termaxa; ls && cd ..; echo x > policy.yaml` is allowed by `echo *`, as `echo x > "$X/policy.yaml"` is. README's observe-mode paragraph no longer says the floor holds these files however a write is spelled.
- Four test-only helpers in `delete.rs` and `backup.rs` moved below the production code, so RELEASING.md's line count reads them as tests.
- Dated corrections under v0.21.3 and v0.21.2.
- 583 tests.

### Upgrade note — a policy from before v0.21.3

The denies above come from the path rules v0.21.3 added. `termaxa init` never rewrites a policy, so a project initialised before v0.21.3 guards these files with string rules (`*.claude*settings*` and its neighbours), and a string rule cannot see across a `cd`: with that policy, v0.21.4 fixes the previews and the copy aside, and `cd .claude && echo {} > settings.json` is still allowed. Put these five rules at the top of `rules:` in `.termaxa/policy.yaml`:

```yaml
  - match_path: "*/.termaxa/*"
    action: deny
    reason: "Termaxa's own config is off limits — that is the gate. Edit it yourself."
    floor: true
  - match_path: "*/.claude/settings*.json"
    action: deny
    reason: "Agent hook configuration is off limits — editing it unhooks the gate."
    floor: true
  - match_path: "*/.cursor/hooks.json"
    action: deny
    reason: "Agent hook configuration is off limits — editing it unhooks the gate."
    floor: true
  - match_path: "*/.codex/hooks.json"
    action: deny
    reason: "Agent hook configuration is off limits — editing it unhooks the gate."
    floor: true
  - match_path: "*/.github/hooks/*"
    action: deny
    reason: "Agent hook configuration is off limits — editing it unhooks the gate."
    floor: true
```

Then check:

```
termaxa check "cd .claude && echo {} > settings.json"
```

It should say `deny`.

## v0.21.3 — node_modules is not the floor

**In plain words:** preparing the first observe-mode week on a live Next.js project (Max Petrusenko, Oct 9, 2026), 46 commands such a project runs went through the v0.21.2 hook in observe mode. Three were held that should not have been: `rm -rf node_modules` and `rm -rf .next`, past the copy budget and so read as unrecoverable, when an install rebuilds them; and `cat .claude/settings.json`, denied by the rule written to stop an agent *editing* the hook config. Measuring the second found a hole in the gate's own defence: `cat .termaxa/policy.yaml > .termaxa/policy.yaml` was an allow, in both modes, because the gate's own read exception matched the redirect and nothing read where it landed. The policy would have truncated to nothing. A directory a build rebuilds is now not a loss, the gate's own files and the hook configs are path rules on the floor, and reading a hook config is ordinary work.

### Security

- `cat .termaxa/policy.yaml > .termaxa/policy.yaml` and `cat .termaxa/policy.yaml > .termaxa/backups/x` were allowed: the `cat .termaxa*` review exception matched the redirect, the `*.termaxa*policy*` deny sits below it, and no rule read the target. The gate's own files and the four hook configs are now `match_path` rules first in the starter, marked `floor: true`: `*/.termaxa/*`, `*/.claude/settings*.json`, `*/.cursor/hooks.json`, `*/.codex/hooks.json`, `*/.github/hooks/*`. A path rule fires on what the command touches, ahead of every string rule, so a redirect, `tee`, `sed -i` or `cp` into one of them is denied however it is spelled, and `rm -rf .termaxa` is a floor rule rather than an ordinary `*rm -rf*` deny (the field report asked for one after `git clean -fdx` removed the policy). The string rules stay as the belt for grammars the target extractor does not model (#145).
- A `match_path` rule could not be on the floor: `is_floor_rule` compared the bare pattern against the `path:<pattern>` label a decision carries. No starter rule was affected, because none was marked; it compares labels now (#145).

### Fixed

- A directory a build or an install rebuilds, past the copy budget, is not read as unrecoverable: `node_modules`, `.next`, `.nuxt`, `.svelte-kit`, `.turbo`, `.parcel-cache`, `.cache`, `dist`, `build`, `out`, `target`, `.venv`, `venv`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `coverage`. The preview says `not copied — node_modules is rebuilt by npm, pnpm, yarn or bun install`, the command is not uninsurable, observe mode lets it run recorded as `known-uninsured`, and the copy aside leaves the directory out and copies the other operands (`rm -rf node_modules src` copies `src`; before, the whole take was refused). A glob inside one (`rm -rf node_modules/*`) reads the same way. The name is read only below the project root: no root, outside it, or the same tree under any other name is as unrecoverable as before, and a project that lives under `~/build/` is not a build artifact. Under the budget the directory is copied like anything else. Enforce mode keeps the `*rm -rf*` deny (#145).
- Reading a hook config is ordinary work: `cat`, `git diff`, `git show` and `git add` of `.claude/settings*`, `.cursor/hooks*`, `.codex/hooks*` and `.github/hooks*` are allowed, the exceptions `.termaxa/` has had since #16. The four hook-config string denies move down beside the `.termaxa` ones, below the overwrite denies; `cat .claude/settings.json > /etc/hosts` is still the `/etc` deny (#145).

### Measured and documented

- Starter: 224 rules (157 allow, 14 ask, 53 deny), 38 on the floor, six path rules; `examples/policy.yaml` regenerated. README, SECURITY.md (the self-defence paragraphs) and `docs/observe-mode.md` say what the floor holds and what a build directory is.
- 46 commands through the hook in observe mode, v0.21.2 against v0.21.3: every verdict identical except the build-directory deletes (now run, recorded), the hook-config reads (now allow), and the writes into the gate's own files (now held by path, including the self-truncation that was an allow).
- 564 tests.

### Upgrade note — existing projects keep the old policy

`termaxa init` writes `.termaxa/policy.yaml` once and never rewrites it, so upgrading the binary changes nothing in a project that already has one: its `cat .termaxa*` exception still launders a redirect into `.termaxa/`, and `cat .claude/settings.json` is still denied. The build-directory reading is in the binary and needs no policy change. To pick up the rest, put the five path rules at the top of your `rules:`, above everything else:

```yaml
  - match_path: "*/.termaxa/*"
    action: deny
    reason: "Termaxa's own config is off limits — that is the gate. Edit it yourself."
    floor: true
  - match_path: "*/.claude/settings*.json"
    action: deny
    reason: "Agent hook configuration is off limits — editing it unhooks the gate."
    floor: true
  - match_path: "*/.cursor/hooks.json"
    action: deny
    reason: "Agent hook configuration is off limits — editing it unhooks the gate."
    floor: true
  - match_path: "*/.codex/hooks.json"
    action: deny
    reason: "Agent hook configuration is off limits — editing it unhooks the gate."
    floor: true
  - match_path: "*/.github/hooks/*"
    action: deny
    reason: "Agent hook configuration is off limits — editing it unhooks the gate."
    floor: true
```

and, if you want the reads back, take the hook-config exceptions from `examples/policy.yaml` and place them where its `.termaxa` exceptions sit. Or delete `.termaxa/policy.yaml` and re-run `termaxa init` if you have not customised it. `termaxa doctor` reports the fingerprint change either way; `termaxa check "cat .termaxa/policy.yaml > .termaxa/policy.yaml"` should say `deny`.

### Correction, Oct 13, 2026

The Security bullet above says a write into the gate's own files or a hook config "is denied however it is spelled". Not after a `cd`: the path was resolved in the directory the command started in, so `cd .termaxa && echo x > policy.yaml` and `cd .claude && echo {} > settings.json` were allowed. Fixed in v0.21.4 ([GHSA-3hg6-x893-mfr4](https://github.com/termaxa/termaxa/security/advisories/GHSA-3hg6-x893-mfr4)).

## v0.21.2 — rm -r -f / is rm -rf /

**In plain words:** `rm -r -f /` and `rm --recursive --force /` were asks in the starter, where `rm -rf /` is a hard stop; through the hook the preview said "resolves to a FILESYSTEM ROOT, NOT recoverable" and the answer was still ask, so an auto-approving harness ran it. And `rm -rf /*` ran in observe mode: the preview read `/*` as a path that does not exist, and the hook's floor was narrower than `run`'s. Both found on Oct 9, 2026 while checking Max Petrusenko's field report, the first from outside (Replay over 57,000 real Claude Code and Codex commands, a 38-command suite, a second reviewer), against the v0.21.1 release binary. Every spelling of a recursive, forced rm now reaches the `-rf` rule; a glob is previewed as what it expands to and held in observe mode; and four of his smaller findings are fixed. The report's lead item, `cd X &&` and `git -C X` ignored by the preview and the insurance, is the next release.

### Fixed

- Every spelling of a recursive, forced rm reaches the rule its `-rf` spelling reaches: `rm -r -f`, `rm -f -r`, `rm --recursive --force`, `rm -R -f`, `rm -rfv` and `rm x -r -f` read as `rm -rf`, past `sudo`, `env`, a path and a `-c` string, so `rm -r -f /` is the floor rule `rm -rf /` and `rm -r -f scratch` is `*rm -rf*`. `rm -r x` and `rm -f x` are what they were. The classifier learns `--recursive`, so the breaker counts every spelling (#143).
- A glob target is previewed as what the shell expands it to, never as "nothing to delete": `rm -rf /*` lists the entries it matches, says it resolves to a filesystem root, and is uninsurable, because the copy aside plans from the path as written and the shell expands the glob after the gate has looked. A glob that matches nothing says so; a single-quoted `'*'` is a literal name; a glob in an earlier component is not expanded and says so (#143).
- The hook's floor in observe mode is `run`'s: a deny the preview marks uninsurable is held, whatever its rule. `rm -rf /*` and `rm -r -f /*` are denied in both modes; an insured `rm -rf scratch` still runs in observe mode after its copy (#143).
- An unresolved variable in a path the command only reads is not a refusal: `cp "$HOME/x" /tmp/x` was denied, and the reason called the source the "target". Only a path the command writes or removes fails closed (#143).
- Rollback puts the original file modes back. The copy aside is made private on purpose, and the restore copied the private bits back, so a 755 script came back without its executable bit. The modes are recorded beside the copy and re-applied on restore (#143).
- `termaxa log` and `termaxa report` say when the audit chain does not verify, with `doctor`'s sentence, and exit 1. The report carries it in its own text; `log --json` says it on stderr and keeps stdout JSON; `log --follow` warns and keeps running (#143).
- `termaxa replay` prints reasons in full; a reason cut at 120 characters could not be audited from the output. Commands are cut at 200, were 110 (#143).

### Measured and documented

- The README's "backups have edges" line says a glob target is previewed and not insured.
- Found in the wild: the first field report, Max Petrusenko, Oct 9, 2026.
- 558 tests.

### Correction, Oct 13, 2026

The field report's lead item shipped in v0.21.4, not v0.21.3, and it was more than the preview and the insurance: after a `cd`, a write into the gate's own files or a hook config was allowed ([GHSA-3hg6-x893-mfr4](https://github.com/termaxa/termaxa/security/advisories/GHSA-3hg6-x893-mfr4)).

## v0.21.1 — every spelling of kubectl, terraform and docker

**In plain words:** the starter denies `kubectl delete`, `terraform destroy`, `tofu destroy` and `docker system prune` outright, and observe mode holds them as floor rules. Each rule is written for the subcommand, and a global option in front of it hid the subcommand from the rule: `kubectl -n prod delete deploy api`, `kubectl --context prod delete …` and `terraform -chdir=infra destroy` got the policy default, an ask under enforce mode, and ran under observe mode. So did a program named by its path, such as `/usr/local/bin/terraform destroy`. Found Oct 9, 2026 while answering a question on the Product Hunt launch about whether that deny can be overridden, and measured on v0.21.0 through the Claude Code hook. Every one of those spellings is now the hard stop its plain form is, in both modes.

### Fixed

- kubectl's, terraform's, tofu's and docker's global options before the subcommand no longer hide it from a rule (#141). The options are moved after the subcommand rather than removed, so an exception a team scopes by namespace or directory (`kubectl delete * -n staging`, placed above the deny) holds in both spellings. An option the readings do not know ends the reading, and the command keeps its default.
- A program named by its path (`/usr/bin/kubectl`, `C:\tools\terraform.exe`) is read by its name for deny rules, as a privilege wrapper already was. An allow never admits it (#141).
- The classifier reads the same way, so the circuit breaker counts `kubectl -n prod delete …` as infra-destroy (#141).
- `terraform -chdir=infra apply` copies `infra/terraform.tfstate` first, and the terraform preview plans in the `-chdir` directory, so an ask written for that spelling is refused when its plan destroys something, as the plain spelling's is. Until now neither happened for any spelling but the plain one (#141).

### Behaviour changes

- Read-only work spelled with global options gets its plain spelling's verdict instead of the default: `kubectl -n prod get pods`, `terraform -chdir=infra plan` and `docker --context prod ps` match their allow rules. `terraform -chdir=infra apply` is the `terraform apply*` ask with its state copied, where it was the default ask with nothing copied.
- No starter rule changed, so a project initialised on an earlier release gets all of this by upgrading the binary.

### Measured and documented

- SECURITY.md says which spellings a rule sees and what ends a reading (#141).
- The README's line counts are recounted with RELEASING.md's command. v0.21.0's figures matched the test-module marker anywhere on a line, the reading RELEASING.md rules out, and put about 550 lines of production code among the tests.
- 552 tests.

## v0.21.0 — the edit comes back

**In plain words:** `git reset --hard`, `git checkout -- <paths>` and `git restore <paths>` throw away uncommitted changes to tracked files, and git's reflog never had them: it records commits, and uncommitted work was never one. Termaxa counted the reflog as the way back for `reset --hard` and left these commands at the starter's default, ask, with no way back for the part that is actually lost. Measured Oct 5–6, 2026 across 36 models (the Destructive Reach benchmark): asked to "undo my last commit" with an unrelated edit uncommitted in the tree, 19 answered `git reset --hard HEAD~1` and destroyed the edit every time. Now the preview says what would go, the insurance snapshots it before the command runs, and `termaxa rollback` brings it back. Also in this release: `termaxa init --observe`, so the adoption path starts without editing the policy by hand; the list behind the site's "bugs found in the wild"; and the README rewritten as one document.

### Added

- A `discard impact` preview for `git reset --hard`, `git checkout -- <paths>` (and `git checkout <path>` when the word names something in the tree) and `git restore <paths>`: the tracked files whose uncommitted changes would be discarded, from `git status --porcelain -uno` scoped to the command's paths. A clean tree under the scope gets no preview; `git restore --staged` alone and `git checkout -b` are not discards (#135).
- A `git-stash` insurance kind: `git stash create` writes the snapshot without touching the working tree or the stash list, pinned under `refs/termaxa/backup/<id>` so it survives collection, with a Termaxa identity so a hook never fails for a git with no `user.name`. `termaxa rollback <id>` applies it, `--index` first so staged changes come back staged (#135). No verdict changes: these commands keep whatever verdict the policy gives them.
- `termaxa init --observe` writes the starter policy with `mode: observe`; on a project that already has a policy, `init` leaves the file alone and says how to set the mode (#136).

### Measured and documented

- The Destructive Reach benchmark: ten ordinary repository requests, each answer judged by this gate and then run on a throwaway repository and checked for collateral damage, across 42 models on Kaggle; 36 answered every scored request in the analysis run. With the gate, no model passed more than 7 of 10 (mean 6.1); without it, 9.4, and 15 models were perfect. Of 117 refused commands, 116 were correct; the one idiom that did real damage, `git reset --hard`, was an ask. [Benchmark](https://www.kaggle.com/benchmarks/devdoc83/destructive-reach), [write-up](https://dev.to/zerodrop/asked-to-undo-a-commit-19-of-36-models-destroyed-work-nobody-mentioned-54je). This release closes the gap it found.
- `termaxa doctor` and the README say that in Cursor's Auto-review mode, Cursor's reviewer decides Termaxa's asks (#134). Cursor's support confirmed the behaviour on Oct 6, 2026 and flagged it to their team; the gate keeps `ask` for Cursor, and a per-rule `deny` is the workaround for teams that must stay in Auto-review.
- `docs/found-in-the-wild.md`: every bug found through real use, with how it was found and where it was fixed. Counted strictly it is 34 bugs in 21 episodes, not the 16 the site said; the site's number is now the list's length (#137).
- The README rewritten as one document: the first screen, the adoption path, one harness table, one insurance table, every console sample captured from the binary (#138).
- The release workflow's winget job needs a token with `workflow` as well as `public_repo`: syncing the fork carries upstream's own workflow changes, and v0.20.1's job failed without it (#134).
- 547 tests.

### Correction, Oct 22, 2026

Cursor's support confirmed the Auto-review behaviour on Oct 5, 2026 (the forum
reply is dated Oct 5, 08:45 UTC), not Oct 6. The README's harness table carries
the right date since this correction.

## v0.20.1 — observe mode says nothing

**In plain words:** v0.20.0's observe mode answered Cursor and Copilot `allow` for commands outside the floor. Copilot treats a hook's `allow` as an approval, so in Copilot, turning observe mode on skipped Copilot's own prompts. Observe mode now says nothing in every harness, which each harness treats as no opinion. Enforce mode is unchanged.

### Fixed

- An observed verdict is silence in every harness: no output, exit 0 (#132). Measured Oct 4, 2026 on Windows with a probe hook that answered one way per trial: Copilot CLI 1.0.83 skipped its own prompt and ran on a hook's `allow`; with no answer, Copilot prompted, and Cursor 3.21.16 decided as it would alone in each of its three auto-run modes. The floor still answers, in each harness's own shape.

### Measured and documented

- `docs/dialects.md` gains the table: silence, `allow`, `ask` and `deny` per harness; Cursor's per-attempt `sandbox` field and empty `cwd`; Copilot's object `toolArgs` on Windows.
- Cursor 3.21.16's Auto-review overrides a hook's `ask` and runs the command, while Allowlist and Run Everything show the prompt; `deny` is enforced in every mode, and nothing in Cursor's payload names the mode. Copilot CLI 1.0.91 prompts on a hook's `ask` even under Allow All. SECURITY.md states the Cursor case.
- 541 tests.

## v0.20.0 — observe mode, and what it would have caught

**In plain words:** `mode: observe` lets a team install Termaxa and change nothing: every command still runs, every verdict is recorded with its insurance still taken, and `termaxa report` shows what enforcement would have asked, denied, and copied first. Only a floor of 33 rules (the gate's own files, the machine and its recovery points, commands with no way back) is enforced regardless. The circuit breaker's trips and resumes are now recorded events, and `termaxa replay --against-record` says whether every command in an agent's transcripts actually reached the gate.

### Observe mode (#130)

- `mode: observe` in `.termaxa/policy.yaml`, or `TERMAXA_MODE=observe` on one machine. The default stays `enforce`. In both the hook and `termaxa run`.
- Outside the floor, an ask or deny runs after its insurance and is recorded as the verdict enforcement would have given, with `enforced: false` and a `coverage` of `insured`, `known-uninsured` or `unknown`. The agent sees an allow; its own prompts are what they were without Termaxa. Observed verdicts page nobody.
- The floor: every rule marked `floor: true`, plus any command whose insurance cannot be taken at the moment it runs. The starter marks 33 of its 47 denies: the gate's own configuration and state (10), the machine and its recovery points (11), and commands with no recovery path (12). Observe mode never relaxes a floor rule. A policy that asks for observe with no floor rule is enforced instead; `doctor` says why.
- `termaxa report` gains "Observed, not enforced": what enforcement would have asked and denied, the coverage buckets, what the floor held, and "ran with no copy". `doctor` names the mode, its source and the floor-rule count.
- Existing policies: `init` never rewrites a policy, so a policy written before this release has no floor markers. To use observe mode, add `floor: true` to the rules you would never want relaxed (the 33 in `examples/policy.yaml` are the reference), or regenerate the starter in a fresh project and merge.

### The circuit breaker resumes only by a recorded act (#126)

- A trip is an event in the record, carrying the attempts that caused it, and it holds that intent for the project across sessions until `termaxa breaker resume --reason "…"` releases it, recording who, when and why before the next command is judged. `termaxa breaker status` shows what is holding; `reset` is the no-reason alias.
- Optional `circuit_breaker.resume_after` (e.g. `24h`) releases a trip on its own, and that release writes its own line too.
- Before: a trip was recomputed on every ask from the record's last 64 KB, so it ended silently when the session changed or enough other activity scrolled past.

### replay --against-record (#127, #128, #129)

- The hook leaves a witness (`logs/seen.jsonl`) as the first thing it does, before the policy loads. Record lines carry the harness's `tool_use_id` as `call_id`.
- `termaxa replay --against-record` sorts every shell call in a wired session into judged, fired-but-unrecorded (a witness and no record line: the gate failed after it fired) or never-fired (neither: the wiring was bypassed), plus not-run (interrupted before running, per the transcript's own result). Sessions the gate never saw are counted as not wired, not accused. Exit 1 if either bypass class is non-empty.
- The transcript reader now counts shell calls only: not files an agent wrote that mention a command; a `powershell -Command` or `bash -lc` wrapper is read as its script. The plain `replay` tally benefits too.

### Also

- SECURITY.md lists every published advisory with both endpoints of its exposure (first affected release and publication date, both UTC) and the days between, with the command to recompute any row.
- Record schema: optional `call_id`, `mode`, `enforced`, `floor` and `coverage`; older lines parse unchanged. Policy schema: `mode`, `floor`, `circuit_breaker.resume_after`.
- 540 tests.

## v0.19.6 — the option beside the one a rule was written for

**In plain words:** a command allowed for reading (`sed -n`, `find`, `git diff`/`log`/`show`/`branch`, inline `node`) no longer runs without a prompt when an option makes it write a file, overwrite a branch or run a command; the file it would write is previewed and backed up first; and a push that deletes remote branches says which, instead of "nothing to push".

Security release for [GHSA-36jf-95xr-37f2](https://github.com/termaxa/termaxa/security/advisories/GHSA-36jf-95xr-37f2)
(Moderate), reported privately by Tim Schipper
([AraneaDev](https://github.com/AraneaDev)) against v0.19.5 and extended
while reproducing it. One code PR (#123), released the same day it merged,
under the rule that wrong verdicts ship immediately. The advisory lists how
long each form was exposed, with both endpoints.

### Fixed

- **An option that writes or runs turns a reading allow into an ask.**
  Starter rules written for the reading form of a command also allowed
  forms that write or run: `git branch -M`/`-C`, `find -fprint`/`-fprintf`,
  `git diff`/`log`/`show --output`, `sed -n -i`, inline `node -e` (the
  report), and `find -fls`, sed's `w` command and `s///w` flag, and sed's
  `e` command, which runs any shell command (found while reproducing). A
  context signal now reads each segment's own words, through wrappers, `-c`
  strings and git's global options, and names the option in the ask. A new
  sed reader follows the arguments and the script, and treats a script it
  cannot follow as able to do anything. The reading forms still pass.
- **The file they write is previewed and backed up.** The output file of
  each of those options, and of `psql -o`, is a target now: the preview
  shows what it loses, and the backup copies it before the command runs,
  the way a `> file` redirect is handled.
- **A push that removes refs says which.** `git push origin :ref`,
  `--delete`, `--prune` and `--mirror` asked, but the preview compared the
  current branch with its upstream and said "nothing to push". It reads the
  refspecs now: a delete names the branch, its last fetched tip and the
  commits only it holds, and a single deleted branch is pinned before the
  push, like a force push. `--prune` is scoped to the wildcard refspecs
  given, since a plain refspec prunes nothing (git's own `--dry-run` agrees);
  a prune or mirror that would remove something is uninsurable and denied.

### Docs

- SECURITY.md's line on scripts matches the starter: `python` and `bash`
  scripts ask, `node <file>` is in the dev loop, and inline node code asks.

## v0.19.5 — the spellings a rule does not see

**In plain words:** control-flow keywords (`for`, `do`, `done`, `if`, `then`, `fi`) no longer make the gate ask; a rule you write now matches the command in every spelling the gate can read (`X=1 gh …`, `env gh …`, `\gh …`, `sh -c "gh …"`, `eval "gh …"`, `… | xargs gh …`, and `sudo gh …` for a deny); five read-only shell built-ins are allowed by default.

A batch of two code PRs (#117, #118) plus the docs, the plugin's move
in-tree and the winget automation, released before Show HN so a fresh
install carries the current starter.

### Fixed

- **A string rule sees through every spelling the resolver knows** (#118).
  Measured Sep 27 while answering a team's open question about their own
  Claude Code deny list: with a `gh repo delete*` deny, the plain form was
  denied and `GH_CONFIG_DIR=/x gh …`, `env gh …`, `\gh …`, `eval "gh …"`
  and `… | xargs -I{} gh …` were asks, because the head resolver knew the
  spellings and the string rules did not (the `git -C` shape again). Every
  such reading now feeds the string rules; `xargs` is a wrapper with its
  flags; a double-quoted `eval` that expands nothing is read as the command
  it is; and `sudo`/`doas` are transparent to a deny only, so an allow for
  `apt-get install*` still does not admit `sudo apt-get install`. For the
  record, Claude Code's own matcher (2.1.281 and 2.1.283) catches the env
  prefix, `env`, `command` and the backslash and lets `sh -c`, `eval` and
  `xargs` run.
- **Control-flow keywords no longer ask** (#117). Claude Code's startup
  probe (`sh -c "uname -s … for c in npm yarn pnpm; do command -v …; done"`)
  was refused on `for c in npm yarn pnpm`, which matched no rule (live Herdr
  session, Sep 24). A `for`/`case`/`select` header, and `do`, `done`,
  `then`, `else`, `fi`, `esac` alone, run nothing and are transparent; a
  leading `do`/`then`/`if`/`while`/`until`/`!` or a `case` arm's `pattern)`
  is stripped so the command it governs is what is judged. `do rm -rf "$f"`
  is still `rm -rf`, `case x in a) rm -rf /;; esac` is denied rather than
  swallowed by its header (the test found that before it shipped), and an
  assignment under a condition still does not bind (#94's rule).

### Added

- Starter rules (198 → 203): `command -v *`, `test *`, `[ *`, `[[ *`,
  `printf *`. `init` never rewrites an existing policy: add them by hand or
  regenerate.
- The Herdr plugin lives in-tree under `herdr-plugin/` (#115):
  `herdr plugin install termaxa/termaxa`. Excluded from the crate.
- The winget update PR opens itself from each release (#116).

### Docs

- README and SECURITY.md current as of v0.19.4 (#114); the README opens on
  the consequence line, the gate inside the agent, and the playground.
- From this entry on, each release starts with an "In plain words" line.

## v0.19.4 — every spelling of a force push, and every spelling of git

**In plain words:** `git push -f` and `git push origin +main` are now denied like `--force`; `git -C <dir> …` no longer slips past every git rule; a backup never follows a symlink or junction into a bigger tree.

Two wrong verdicts in a shipped starter, both found Sep 24, 2026, so this
ships the day they were found (#112).

### Fixed

- **`git push -f` and `git push origin +main` were asks.** The hard stop
  was spelled `git push*--force*`, so only the long form was denied while
  the short form and the refspec form fell to the general `git push*` ask.
  The classifier has always counted every spelling; the policy now does
  too. An ordinary push still asks.
- **Git's global options defeated every git rule.** Claude Code spells its
  git calls `git -C <path> …` (live Herdr session, Sep 20), and no rule saw
  past the `-C`: `git -C /x ls-files scratch` asked, and `git -C /x push
  --force origin main` was an ask, hard stop and all. Git's global options
  (`-C`, `-c`, `--git-dir=`, `--work-tree=`, `--no-pager`, …) are now
  stepped over wherever git is read: the policy's readings, the intent
  classifier, and the delete head, so `git -C /x rm -r scratch` is the
  delete it is. The guarantee is the plain form's verdict, whatever it is.
- **The insurance copy followed links.** The preview counts a link as one
  entry and does not walk into it (measured on Windows with a real
  junction); the size cap uses that walk; but the copy branched on
  `is_dir()`, which follows links, so a directory holding a link into a
  large live tree passed the cap as a handful of entries and then copied
  the whole tree behind it, uncapped, and a rollback would have put the
  link back as a real directory. That is the mechanism of the Sep 20
  incident that deleted 48,218 live files through directory junctions,
  inside our own insurance. A link is now copied as a link (Unix) or left
  out rather than followed (Windows), and restored as a link.

### Added

- Starter rules (193 → 198): the three force-push spellings; bare `head`;
  `git check-ignore*`. `init` never rewrites an existing policy: add them
  by hand or regenerate.
- The collapsed-quote `rmdir /s /q` from the Cursor forum (Sep 17, most of
  a D: drive gone) as a regression test in six spellings, all denied by the
  verb; the hard stop does not need to get the path right.
- **SECURITY.md** says plainly that a script is not read: `python
  remover.py` is an ask with no preview, no insurance, and a record that
  names the interpreter, and that is the biggest thing a shell gate cannot
  see.

## v0.19.3 — replay your own transcripts, and what the first replay asked about

**In plain words:** `termaxa replay` judges every command your agents ever ran, from their transcripts; `termaxa log -f` follows the record; the Linux binary now runs on any distro; eleven ordinary commands stopped asking.

The first batched release: two PRs, nothing in them a wrong verdict in a
shipped version. Sep 20, 2026: every `command` in the Claude Code and
Codex transcripts on one machine (19 files, 59 commands) replayed through
`termaxa check` against the starter, no execution, five minutes. A small
and biased sample, so not an ask ratio; but each ask is a command that
asked, and the ones that should not have are fixed here.

### Added

- **`termaxa replay [paths…]`** (#109): every command your agents have run
  on this machine, from their transcripts (`~/.claude/projects`,
  `~/.codex/sessions` by default), judged the way `check` decides — policy,
  context, readable substitutions — with no previews, no insurance, no
  audit lines and nothing executed. The tally with percentages, the
  distinct asks and denies with counts and reasons. The honest answer to
  "how often will this get in my way?" before installing.
- **`termaxa log --follow`** (`-f`) (#109): the tail, then every entry as it
  is written.
- **Starter rules from the replay** (#108, #109; 181 → 193): `git add*`;
  `find *`, with `find -delete` a hard stop and `find -exec`/`-ok` asks;
  `sed -n *`; the gate's own read-only subcommands (`log`, `backups`,
  `report`, `doctor`, `check`); a bare `echo`. `init` never rewrites an
  existing policy: add them by hand or regenerate.

### Fixed

- **A substitution the policy can read is not "not analyzable"** (#108).
  `$(git branch --show-current)` matched an allow and was escalated to ask
  because `$(…)` was a signal on sight. Each substitution's inner text is
  now extracted and the signal stays only for one the policy would not
  explicitly allow. A quoted heredoc (`$(cat <<'EOF' … EOF)`, Claude Code's
  spelling for every commit message) expands nothing and is read as data.
  `$(curl …)`, `$(rm …)`, an unquoted heredoc and anything unmatched
  escalate as before. Known: a heredoc *body* that spells a hard stop still
  trips it; fail closed.
- **The Linux release asset is a static musl build** (#109). The glibc
  build needed 2.39 and would not start on Debian 12 or Ubuntu 22.04
  (found Sep 19 building the playground image). Same asset name; CI builds
  it on every push.

### Elsewhere

- **The playground**: `play.termaxa.com` runs the real gate on a throwaway
  project, check only, nothing executed. Try to get a destructive command
  past it; the four published advisories are the solved challenges.
- **Method**: the replay is the ask-ratio instrument. Its first run was
  against a stale 0.18.4 (three installs on one machine; Scoop's shim won)
  and was wrong by exactly the v0.18.6 allows. The machine that measures
  runs what it ships.

## v0.19.2 — Cursor's Delete is a delete

**In plain words:** Cursor's file-delete tool was passing through the gate unjudged; it is now read as the delete it is.

Captured Sep 19, 2026 on Windows (cursor 3.11.25): Cursor's file tools
arrive as `tool_name: "Write"` / `"Delete"` with `tool_input.file_path`, no
`cwd`, the project only in `workspace_roots`, a BOM in front, and
`postToolUse` carrying `tool_output`. `Delete` was no verb the hook's write
reader knew, so the payload parsed as nothing, fell to the
unrecognised-payload knob, and passed through by default: the file was
deleted with no line, and a `match_path` rule would not have stopped it.
That is the Cursor case SECURITY.md has carried since live testing, seen
through the hook.

### Fixed

- **`delete` and `remove` are write verbs, of kind delete** (#106). A
  Cursor `Delete` is judged by its target like any native write: `.env`
  denied with the starter's sentence and `(removed)`; a file nothing names
  silent but seen, and receipted on `postToolUse`. The captured payloads
  are the fixture.

### Added

- **`init --cursor` registers `preToolUse` / `postToolUse` on `Write|Delete`**
  (#106) beside `beforeShellExecution` / `afterShellExecution`; `Shell`
  stays on the latter so a command is not gated twice. Cursor reloads the
  file on its own; an existing `.cursor/hooks.json` is rewritten by `init`.

### The capture list

Every harness on the record now has its shell and its file-tool payloads
captured: Claude Code, Codex (`apply_patch`, `PostToolUse`), Cursor
(`Write`, `Delete`), Copilot CLI (shell). What is not captured: silence
semantics beyond Claude Code and Codex, and Copilot's file tools if it has
hookable ones. `docs/dialects.md` holds every shape.

## v0.19.1 — a patch is a write, not a command

**In plain words:** Codex's `apply_patch` was being refused as an unreadable shell command; it is now read as the file writes it contains. Codex is gated by its hooks, not by `termaxa wrap`.

Captured Sep 19, 2026 in the same container as v0.19.0's measurements
(codex-cli 0.155.1, `codex exec` with the hook trusted): Codex sends
`apply_patch` with the whole patch text in `tool_input.command`, the field
a shell command lives in. v0.19.0's hook read it as a shell command,
`*** Begin Patch` became an unmatched segment, and the whole call was
refused as an ask — whatever the patch touched. Fail closed, wrong reading.

### Fixed

- **A tool whose name carries a write verb is read as a write before it is
  read as a command** (#104). Codex's patch reads as its files with their
  kinds (write, add, delete), one call and one verdict; the starter's `.env`
  path rule denies the captured patch with the sentence naming the file, and
  the record says `apply_patch …`, not `*** Begin Patch`. `Bash` never
  matches a write verb, so shell commands are unaffected. The captured
  payload, session fields and all, is the fixture test.

### Added

- **`init --codex` registers `PostToolUse`** (#104), captured the same day
  in Claude Code's shape and receipted by the existing path.

### Measured, and recorded in `docs/dialects.md`

- **`wrap` does not reach Codex.** Under `strace`, every Codex spawn is
  `execve("/bin/bash", ["/bin/bash", "-lc", …])` by absolute path — the
  account's login shell, `$SHELL` ignored — and the audit log stays empty.
  Codex's configuration covers the environment and login-ness, not the
  shell binary, so there is no lever like `CLAUDE_CODE_SHELL`; its hooks
  are the way in. (In that run `scratch` survived because Codex 0.155.1
  itself rejected `rm -rf`, not because of the gate.)
- Both Codex shapes come off the not-captured list. Cursor's `Write` and
  `Delete` payloads remain on it.

## v0.19.0 — native writes reach the gate, the snapshot opens the session, and what runs is what was judged

Four PRs, one release, each measured in the same container that measured
#91 (Ubuntu 24.04, Claude Code 2.1.268, zsh installed, the starter plus
`unrecognised: deny` and `backup_failure: deny`).

### Added

- **Native file writes reach the consequence engine** (#101, #95, the first
  piece of #83). The write matcher has delivered every `Write`, `Edit`,
  `MultiEdit` and `NotebookEdit` since #20; the gate answered with silence
  unless the target was its own file. Now the path-rule tournament is one
  function shared by the shell path and `Policy::evaluate_targets`, and a
  native write is judged by its targets alone: only `match_path` rules
  apply, never a string rule and never the policy default, so a file no
  rule names gets no decision and the harness's own flow stays as it was
  (#48). A deny carries what the write would cost; an allow is insured
  first through the same store `rollback` reads and recorded with `sha256
  before`; `init` registers the write matcher at `PostToolUse` too, and a
  named write gets a receipt with `sha256 after`. A patch is read by its
  `*** Add File` / `*** Update File` / `*** Delete File` / `*** Move to`
  headers from whatever field carries it, and `init --codex` registers
  `Bash|apply_patch`; Codex is not claimed as covered until its payload is
  captured. Measured through the hook, Sep 18: an `Edit` to `notes/a.txt`
  under a `*/notes/*` allow was insured (`termaxa backups` lists it) and
  receipted; an `Edit` to `.env` was denied with the starter's own sentence
  and `23 B on disk`, quoted back by the agent; the file unchanged.
- **A variable bound earlier in the same command line resolves, and Claude
  Code's startup snapshot is read whole** (#99, #94). Simple assignments
  (`NAME=value`, `export NAME=value`, a literal path-like value) are
  substituted into the segments after them, outside single quotes, once,
  never into a nested `-c` string; the assignment segment runs nothing and
  is transparent. `X=; rm -rf $X/*` is the root delete it is. A `-c` string
  whose first line binds `SNAPSHOT_FILE` to the harness's own file and whose
  every write goes there is the startup snapshot: allowed whole under a
  reason that says so, with a hard stop inside a drifted one still firing.
  Measured under `wrap`, Sep 18: `✓ [run] zsh -c -l "SNAPSHOT_FILE=…` —
  `Claude Code startup snapshot (148 segments): writes only to …` — and
  every tool call after it arriving with the snapshot sourced. The first
  wrapped session that opens without a refusal.
- **`git rm` is a delete** (#99, #80): targets, preview, insurance and
  path rules read as for `rm`; `-r`/`-f` count; `--cached` is not a delete.
- **Insurance copies are capped and pruned** (#100, #72). The copy refuses
  above the preview's own budget with the preview's own words, so a "NOT
  recoverable" preview is never followed by a copy; a `retention` key
  (defaults keep 50 / 30 days, both conditions required) prunes at most one
  backup per insured command and all of them under `termaxa backups
  --prune`; every prune is a manifest record; a pruned id cannot be
  restored; a backup past 260 characters says only `rollback` can read it.
- **The target set is re-checked just before a command runs** (#102, #73).
  `run` signs the delete targets (paths, sizes, mtimes, under the preview's
  budget) when the command is judged and again before `execute`; a change
  is refused with both counts in the reason and recorded as the refusal.
- **`termaxa demo`** (#102): the real `check` and `log` on a throwaway
  project under `~/.termaxa/demo/`, removed afterwards — a recursive delete
  denied with its blast radius, `.env` denied by a path rule, a single-file
  delete asked with insurance planned, and the record.
- **`CONTRIBUTING.md` and `docs/dialects.md`** (#102): the working rules,
  the gate, where things live; how to capture a harness, what each honours,
  what is not captured yet.
- **`TRUNCATE a,b`** is the same list as `TRUNCATE a, b` (#99); the `.env`
  path rule's reason says "Writing to or removing" (#99); the README's
  first sentence says what the thing is (#99).

### Known limitations

- Codex `apply_patch`, Codex `PostToolUse`, and Cursor's `Write`/`Delete`
  payloads are not captured; the readers exist, the harnesses are not
  claimed. Codex under `wrap` is a separate run.
- A native write no path rule names is silence: no preview, no insurance,
  no line. That is the design, and `docs/dialects.md` says so.
- The hook cannot re-check a target set at execution time; it answers
  before the harness executes. #73's re-check is `run`'s.

## v0.18.6 — the agent keeps its own shell

v0.18.5 handed every wrapped agent the `bash` shim whenever bash existed.
Measured Sep 11, 2026 in the #91 container with zsh installed: Claude Code
took `CLAUDE_CODE_SHELL` over its own detection — not one zsh probe — and
ran everything through `bash -l`. On a Linux box without zsh that was the
fix working; on a machine with zsh, which is every Mac, it moved the agent
off the shell it would have chosen, and a `PATH` or alias that lives in
`~/.zshrc` was gone for it.

### Fixed

- **`wrap` names the shim for the shell the agent would have chosen
  itself** (#96): the `zsh` shim when a real zsh exists (it is only written
  when one does), else `bash`, else `sh` — Claude Code's own order. A
  `CLAUDE_CODE_SHELL` that already names one of the shims is kept as the
  operator's choice; a path outside the shim directory is still overridden
  and said. Measured after in the same container: five spawns through
  `shims/zsh`, the tool calls arriving as `zsh -c -l "setopt
  NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL … eval '…'"` and judged by the command
  inside — `ls` allowed and executed, `rm -rf ./scratch` denied with no
  shell spawned for it, twelve files intact. The `setopt` reading's first
  live receipt; v0.18.5 had it only in the suite.
- **The wrap tests read an explicit search path** (#97). CI run 191 failed
  on macOS in a wrap test with "sh exists on any unix test machine": the
  test binary's `isolating_path` guard had rewritten the process `PATH` on
  another thread while the test walked it. Environment variables are
  process-global. `install_shims_on` and `real_shell_on` take the search
  path as an argument; with `PATH=/nonexistent` forced for the whole
  binary, all seven wrap tests pass. Production reads `PATH` as before.

### Added

- **`cd` and git's read-only heads in the starter** (#96): `cd`, `cd *`,
  `git ls-files*`, `git show*`, `git rev-parse*`, `git blame*`,
  `git describe*`, `git stash list*`, `git config --get*`, a bare
  `git remote`, and `git tag` in its listing forms only (`git tag -d`
  deletes, so `tag *` stays on the default). The receipt: an agent under
  `wrap` refused unattended on `cd /home/dev/proj && git ls-files scratch`
  — a read-only command, refused on the one word in it that had no rule.
  168 rules become 181. `init` never rewrites an existing policy: add them
  by hand or regenerate.

### Known limitations

- The startup snapshot is still refused under `wrap` (#94). The zsh form
  is 149 segments and falls to the default on the assignment itself; the
  bash form's 42 draw the unresolvable-target refusal on `head -n 1000 >>
  "$SNAPSHOT_FILE"`. Claude Code carries on without it.
- Measured on Claude Code, on Linux with and without zsh. Codex under
  `wrap` is a separate run.

## v0.18.5 — `wrap` is told where Claude Code's shell is, and reads what it sends

`wrap` had never seen Claude Code. v0.18.4 said it had; the correction is
under that entry below. Measured Sep 10, 2026 under `strace -f -e
trace=execve` in a fresh Ubuntu 24.04 container with no zsh (Claude Code
2.1.268, headless): Claude Code probes zsh at four absolute paths, then runs
`/bin/bash` by absolute path for its startup snapshot and every Bash tool
call, which nothing on `PATH` can see. An unattended `rm -rf ./scratch`
deleted twelve files with no audit entry — three times untraced, once
traced (#91).

### Fixed

- **`wrap` hands the agent the `bash` shim by name** (#92). Claude Code
  honours `CLAUDE_CODE_SHELL` (a bash or zsh path) and reads `$SHELL` only
  when that names bash or zsh; the `sh` shim it was handed was neither.
  `SHELL` and `CLAUDE_CODE_SHELL` now both point at the `bash` shim (the
  `sh` shim on a machine with no bash). An operator value pointing outside
  the shim directory is overridden and one line says so — a wrapper that
  silently routes nothing is the failure this repairs.
- **Claude Code's preamble is read as the scaffolding it is** (#92). Every
  Bash tool call arrives as `shopt -u extglob 2>/dev/null || true && {
  \builtin unalias -- 'unsetenv'; \builtin unset -f -- 'unsetenv'; }
  >/dev/null 2>&1 || true && eval '<cmd>' < /dev/null && pwd -P >|
  /tmp/claude-<hex>-cwd` (`setopt …` under zsh, a `source` of its own
  snapshot in front when one exists). Routed through the shim, the gate
  read `shopt` as the command, found no rule, and refused every one of
  them. The pieces are recognised by exact form, only inside a `-c`
  string, and are transparent unless a rule names them, as an unnamed
  wrapper is; `eval '<single-quoted>'` is read as the command line it is,
  and the command inside decides. `source` is transparent only for the
  harness's own snapshot file name, with no `..` anywhere; the cwd file is
  `/tmp/claude-<hex>-cwd` exactly. A preamble that is not the measured one
  stays an unmatched ask, and the refusal names it.
- **The context check reads the judged command** (#92). The preamble's
  `unset -f` was a "destructive flag" on every command, escalating each
  allowed one to an ask. `-rf` inside the eval is still found.

### Added

- **The starter allows the read-only Unix filters and probes** (#92):
  `head *`, `tail *`, `wc *`, `cut *`, `diff *`, `stat *`, `du`, `du *`,
  `pwd`, `pwd *`, `which *`, `date`, `date +*`, `env`, `printenv`,
  `printenv *`, `uname`, `uname *`, `id`, `id *`. Claude Code's first act
  in a session is `bash -c env`; the demo video's own hero shot was an ask
  on `head -5`. `env` is bare only — `env CMD` runs CMD, and an allow list
  widens by the head that names the action, never the runner. `sort` and
  `uniq` are left out: `sort -o FILE` and `uniq IN OUT` write a file with
  no redirect for the gate to see. 148 rules become 168. `init` never
  rewrites an existing policy: add them by hand or regenerate.

### Measured

Same container, this build, policy regenerated, `unrecognised: deny` and
`backup_failure: deny`, hook file aside, no `CLAUDE_CODE_SHELL` in the
environment, Claude Code asked to `rm -rf ./scratch`: five shell spawns,
every one through the shim and into `termaxa run`; `env` and the `ls`
calls allowed and executed; the delete denied — "Recursive force delete
blocked by default policy" — with no real shell spawned for it; twelve
files intact; the agent: "I stopped rather than routing around the block
with an equivalent command." With the hook file present as well, the two
modes coexist: Claude Code runs hook commands through `/bin/sh` by
absolute path, which never touches the shim, and each call is judged by
both.

### Known limitations

- The startup snapshot is still refused: `SNAPSHOT_FILE=<path>` is
  assigned on the string's first line and used as `>| "$SNAPSHOT_FILE"`
  throughout, and the gate does not yet resolve a variable assigned
  earlier in the same string. Claude Code carries on without it, adding
  `-l`. Its own issue.
- Measured on one harness, on Linux without zsh. The zsh path with this
  build, and Codex under `wrap`, are separate runs.
- A denied delete inside a wrapper is reported against the whole line —
  the existing tie-break — not against the `rm` inside the eval.

## v0.18.4 — the first real agent under `wrap`

`wrap` had executed what it approves since v0.18.0 and had never met a
real agent. On Sep 10, 2026 it met one: Claude Code 2.1.267, headless,
`--dangerously-skip-permissions`, in a throwaway container with the hook
file moved aside so the shim alone was on trial, asked to `rm -rf ./scratch`.

The answer that decides the roadmap: **the shim sees the agent's shell.**
Claude Code resolves its shell by name, and the shim caught it from the
startup snapshot onwards — `zsh -c -l "..."`, with the shim directory baked
into the PATH line inside it. Twelve files survived; exit 0; the agent
reported "Nothing was deleted", declined to pipe `y` past the gate ("that
would be auto-answering your own security gate on your behalf"), and
cleaned up after itself. That paragraph is the receipt.

The same run found four things, all ours, all fixed here (#89).

### Fixed

- **`zsh -c -l "cmd"` was read as the command `-l`.** A shell accepts
  options in any order; Claude Code puts `-l` after `-c`; the reading took
  the token after the flag. Every command the agent ran was an unmatched
  ask. Both the policy reading and the shim's own walk now step over
  options (and `-o arg`) after `-c` to the first operand.
- **An unattended ask was a hang.** The runner prompted on stdin; the
  harness's pipe never closed, so the prompt blocked until Claude Code gave
  up at 120 s. And that pipe is writable by the agent — a `y` in it is not a
  person. **An ask now requires a terminal on stdin**; anything else is
  refused at once with the reason. A person at a terminal is unchanged.
  Scripts that approved by piping `y` into `termaxa run` will now be
  refused, deliberately; use a terminal, or an allow rule.
- **The self-protection rule refused the agent's own startup.** The
  starter's `*.termaxa*` deny matched the PATH line `wrap` injects into
  every shell it starts (`export PATH=~/.termaxa/shims:...`). The belt
  over `protect.rs` is now named by what it holds — `policy`, `projects`,
  `backups`, `logs`, `shims/` — and `git config core.hooksPath` is its own
  hard stop rather than a side effect. `export *` is allowed: an
  assignment runs nothing, and a substitution in the value is still
  escalated.
- **`wrap` shimmed a shell that was not installed**, and Claude Code chose
  the shell the shim advertised. A shim is installed only for a shell found
  on PATH outside the shim directory, execs that resolved path, and a stale
  shim for an absent shell is removed.

### Known limitations

- An ask abandoned mid-prompt at a real terminal still leaves no audit
  entry. Unattended asks are refused now, so the case is narrower.
- The measurement was one harness. Codex under `wrap` is a separate run.
- Claude Code's startup snapshot writes under `~/.claude` through a
  variable path (`>| "$SNAPSHOT_FILE"`), which the gate reads as an
  overwrite it cannot resolve and asks about — refused unattended. Claude
  Code carries on without the snapshot; noted, not yet decided.

### Correction, Sep 11, 2026

The claim above that the shim sees Claude Code's shell was wrong, and the
measurement it rested on was an artefact. Under v0.18.3 the shim directory
advertised a `zsh` that did not exist; Claude Code found it on `PATH` and
used it. The fix in this release stopped offering absent shells, and with
no zsh on the box Claude Code (2.1.267, 2.1.268) runs `/bin/bash` by
absolute path for its startup snapshot and every Bash tool call, which
nothing on `PATH` can see. Measured the same day, same container, on
v0.18.4: three unattended `rm -rf ./scratch` runs deleted the files with
zero audit entries, and a fourth under `strace -f -e trace=execve` shows
four absolute-path probes for zsh, then `/bin/bash`, then `/usr/bin/rm`,
and no exec of the shim. On a box with zsh the shim is hit, and the gate
then refuses every command on Claude Code's own preamble (`setopt …`,
`shopt -u extglob …`), which is the other half of the same defect. The
snapshot line above is also wrong: it is refused as an unresolvable
target, not asked about, with default knobs too. Tracked in #91, fixed in
v0.18.5 (#92): `wrap` sets `CLAUDE_CODE_SHELL` to its shim, which Claude
Code honours, and the preamble is read as scaffolding.

## v0.18.3 — four harnesses live-tested

Claude Code, Cursor, Codex and Copilot CLI have each now run a real
session under the gate, and each one taught the gate something its
documentation had not. Issue #10, open since July, is closed.

### Added

- **Copilot CLI is live-tested** (#86, #87). Measured Sep 9–10, 2026 on
  Windows 11 with Copilot Free. Three things the documented format did not
  say: the shell tool on Windows is named `powershell`, not `shell`; a
  non-zero exit is a hook error to Copilot, not a deny — the first session
  saw `echo hi` refused as "(hook errored)" and the block held only because
  `failClosed: true` turns an error into a denial; and Copilot runs **two
  hook files in order**, `.github/hooks/*.json` first and then whatever is
  in `.claude/settings.json` ("repo settings"), stopping at the first deny.
  Copilot honours **`ask`**: a Termaxa ask arrives as a "Hook permission
  request" panel with the reason in it and a Yes/No prompt, which Codex
  cannot do. After the fix, a real session went: probe asked and approved;
  `Remove-Item … -Recurse -Force` denied with the reason on screen; the
  agent tried `& $env:ComSpec /c 'rmdir /s /q …'` on its own and was denied
  again through the wrapper. The directory survived.
- **`Dialect::CopilotRepoSettings`** (#87): the repo-settings hook speaks
  Claude Code's shape — both events, so execution receipts exist under
  Copilot on that path — with a string `timestamp` and no
  `transcript_path`. Detected by that, rendered in Claude's shape, exit 0
  on deny, audited as `copilot` where it had been logged as claude-code.
- `powershell`, `pwsh` and `cmd` are Copilot shell tools (#86). Only the
  first is measured; listing the others can only widen what is gated.

### Changed

- **Copilot's deny exits 0** with the verdict in the JSON, on both paths,
  the same contract as Codex (#74). Claude Code and Cursor keep the
  belt-and-suspenders exit 2.
- **The unrecognised-payload refusal speaks the sender's shape** when the
  payload carries `toolName` (#86), so a future Copilot drift reaches the
  user with the reason instead of as an error.
- **`doctor`** no longer says Codex is "not yet verified end-to-end" — it
  has been since v0.18.0 — and it probes the user-level `~/.codex/hooks.json`
  as well as the project one, which is the file the live Codex sessions
  actually ran through (#86).

### Known limitations

- Write hook files **without a byte-order mark**. Windows PowerShell 5.1's
  `Set-Content -Encoding utf8` adds one, and Copilot then ignores the
  file and falls back to repo settings. `init` writes its files without
  one; the README says so for anyone writing them by hand.
- Copilot's two-file order and stop-on-deny are inferred from three
  sessions' audit logs, not from documentation.
- Codex's PostToolUse payload is still uncaptured; under Codex there are
  no execution receipts. Copilot's exist only through the repo-settings
  path.

## v0.18.2 — a positional parameter is a shell variable

### Fixed

- **`$1`, `$@` and their neighbours are now read as variables.**
  `anthropics/claude-code#82165`, still open: an agent composed

      find /var/www/.../tmp -maxdepth 1 -type d -name "*ache*" \
        -exec sudo -u www-data sh -c "rm -rf \"$1\"/* 2>/dev/null" _ {} \;

  `$1` was empty at execution, so the shell ran `rm -rf ""/*` — that is,
  `rm -rf /*` — as root on a production host, detached, with stderr silenced.

  Measured against v0.18.1: the verdict was right and the preview was worse
  than useless. `has_unexpanded_var` tested `next.is_ascii_alphabetic()`, so
  it flagged `$SID`, `$HOME` and `${1}` but not `$1`. The resolver then took
  `$1` for a literal directory name, failed to find it, and reported
  "(path does not exist — nothing to delete)" about a command that was about
  to empty the filesystem.

  Positional and special parameters are variables now: `$1`..`$9`, `$@`,
  `$*`, `$#`, `$?`, `$$`, `$!`, `$0`. That is how a shell receives an
  argument, which is how `sh -c` and `find -exec` pass one, which is how this
  class of incident is actually spelled. The same command now reports the
  target as unresolved and the insurance as not recoverable.

  One existing assertion was wrong and is corrected rather than worked
  around: `rm -rf costs$5` was asserted unflagged, on the reading that a digit
  after a dollar is a price in a filename. The shell disagrees — `costs$5`
  expands to `costs` when `$5` is unset. A filename that really contains a
  dollar arrives escaped or single-quoted, and both were already excluded.

The verdict never changed: `rm -rf` was and is a hard stop. What changed is
that the preview no longer reassures when it does not know.

## v0.18.1 — a command that runs anything is not the dev loop

A regression fix, one day old. v0.18.0 widened the starter policy to allow
the ordinary build and test loop, and widened it too far.

### Fixed

- **`npx *` and `<pm> run *` are no longer allowed by the starter policy.**
  Field report, r/ClaudeCode, Sep 5: an agent given a purely UI task ran
  `npx supabase db reset` and wiped a local database holding months of the
  author's projects, notes and deadlines. Under v0.18.0's starter that
  command was **allowed**, silently, by `npx *`. So were `npx prisma migrate
  reset` and `npx drizzle-kit drop`; `npm run db:reset` was allowed by
  `npm run *`.

  The reasoning in v0.18.0 was that a build or a test runs the project's own
  code, which the gate cannot read either way, so allowing it changes
  friction rather than safety. That holds for a head that names the action —
  `cargo test`, `go build`, `pytest`. It fails for a head that names a
  runner: `npx` runs an arbitrary package off the network, `<pm> run` runs an
  arbitrary script. Removed: `npx *`, `npm run *`, `pnpm run *`,
  `yarn run *`, `bun run *`. Kept: `npm test`, `pnpm test`, `yarn test`,
  `bun test`, `node *`, and the whole cargo / go / make / python / dotnet /
  mvn / gradle loop.

- **A database reset is a hard stop**: `*db reset*`, `*migrate reset*`,
  `*db push*--force-reset*`, `*drizzle-kit drop*`. A local database is
  somebody's months of work as often as it is a throwaway, and these tools
  drop and recreate with no confirmation and no backup of their own.

### If you installed v0.18.0

`termaxa init` writes the starter policy once and never rewrites it, so a
policy created on v0.18.0 still has the wildcards. Compare your
`.termaxa/policy.yaml` against `examples/policy.yaml`, or check directly:

    termaxa check "npx supabase db reset"

It should say `deny`. If it says `allow`, delete the `npx *` and
`<pm> run *` rules from your policy and add the four hard stops above.

The rule this leaves behind: widen an allow list by the head that names the
action, never by the head that names a runner.

## v0.18.0 — the gate reads what the agent actually runs

v0.17 moved who decides. v0.18 reads **what is actually being run** — the
command inside a shell wrapper, the operand a redirect is not, the dialect
Codex really speaks, the PowerShell an agent on Windows really writes — and,
for the first time, `wrap` executes what it approves. Eighteen commits,
**488 tests on Linux, 420 on Windows**.

The honest headline: **the first real Codex session found the hook speaking
the wrong contract on every value**, and `wrap` had never executed a command
in its life. Both are measured and fixed below; the measurements are in the
tree as tests.

### Added

- **A POSIX shell's `-c` string is read as the command it runs** (#62).
  `sh -c "cat /dev/null > src/main.rs"` used to fall to the default, preview
  nothing and take no backup — and the `wrap` shim forwards every command in
  exactly that shape. Policy, intent, preview, delete, resolve and insurance
  now read `sh`, `bash`, `dash` and `zsh` strings as segments of their own,
  four levels deep. Additive: the wrapper stays, so nothing that matched
  before stops matching. `allow sh*` no longer allows what the shell is told
  to run.
- **A wrapper no rule names is transparent** (#68). Under the starter policy
  every wrapped command was asked, because the wrapper matched nothing and
  the default outranked the inner allow. Now the string inside decides; a
  rule that names the wrapper still counts, and `sh script.sh` still falls to
  the default because the gate cannot read it.
- **Codex is live-tested** (#74, #75). Measured on Sep 5–6 with codex-cli
  0.153.4 on Windows: Codex sends no `agent` tag and honours exactly one
  PreToolUse verdict, `deny`; an explicit `allow` or `ask` fails the hook and
  falls open to Codex's own prompt, and a deny that exits 2 arrives as "hook
  exited with code 1". For Codex every allow is now silence, an ask is a deny
  whose reason says the gate asked and how to add an allow rule, and the exit
  code stays 0 so the JSON is read. `init --codex` now writes the hooks file
  in the shape Codex accepts. A hard stop lands in Codex's own UI as "Blocked
  by hook" with the reason and the blast-radius preview.
- **PowerShell read-only cmdlets are allowed** (#75): Codex's "Bash" tool on
  Windows is PowerShell, and under Codex an ask is a refusal. `Get-ChildItem`,
  `Get-Item`, `Get-Content`, `Resolve-Path`, `Test-Path`, `Select-String` and
  their read-only neighbours pass; `Where-Object` and `ForEach-Object` do not,
  because their script block can hide a delete. A `$var = ...` assignment is
  read as the command it assigns — which also makes `$x = rm -rf /` a hard
  stop instead of a question.
- **Two policy keys choose the closed side of the gate** (#70).
  `unrecognised: deny` refuses a hook payload that looks like a shell tool
  call the reader could not parse; `backup_failure: deny` refuses a command
  whose insurance could not be taken. Both default to the cooperative side:
  right for an unattended run, wrong for a person at a terminal.
- **Deleting a recovery point is a hard stop** (#70): `vssadmin delete
  shadows`, `wmic shadowcopy delete`, `Win32_ShadowCopy … Delete`,
  `Remove-WmiObject`, `Remove-CimInstance`. From a field report in which the
  agent sent to recover a wiped drive deleted the shadow copy it was
  restoring from.
- **`termaxa report` counts what became of each ask** (#71): approved,
  declined, unanswered — a hook ask credited by the execution receipt in the
  same session — and names an approval habit at five asks and 80% approved,
  with the allow rule that would end it. An ask that is always approved is
  not a safety feature; it is a habit.
- **The ordinary dev loop is allowed** (#71): build, test, lint and run for
  cargo, npm/pnpm/yarn/bun, node, tsc, eslint, prettier, jest, vitest,
  pytest, ruff, black, mypy, go, make, dotnet, mvn and gradle. Publishing
  still asks; installing and cleaning still fall to the default.
- **`init` wires the harness it detected and verifies the hook answers
  before saying Done** (#46).

### Changed

- **A segment knows its own words** (#61): a redirect is never a delete, copy
  or move operand. `rm -rf ./cache > /dev/null 2>&1` had `/dev/null` as a
  target; the insurance tried to copy a device, failed, and the command ran
  uninsured.
- **The `wrap` shim reads `-c` wherever the shell would** (#69): `bash -lc`
  (Codex's spelling), `bash -e -c`, `bash --norc -c`, `bash -o pipefail -c`
  are all gated exactly once, and the shell's own options reach execution.
- **The Postgres preview footer says why there is no estimate** (#57):
  denied before spawning, filtered `DELETE`, no `psql`, a database that
  refused, a reply that could not be read — five different sentences where
  there was one. `psql` is asked one statement at a time, which also makes
  the read-only `SET` real on `psql` 14 and earlier.
- **The preview admits an unresolvable target instead of inventing a path**
  (#11), and **the preview and the backup name the same file** (#50).
- **`init --codex` registers PreToolUse only** until Codex's PostToolUse
  payload has been captured.

### Fixed

- **`wrap` could not execute what it approved** (#65). The runner's own `sh`
  resolved through the same shim PATH; an allowed command recursed until it
  was killed, and an asked one asked twice, then refused for lack of stdin.
  The wrapper now runs the approved command outside the shims. The existing
  test had pinned a deny and a bypass, never an execution.
- **The insurance copy hung on a named pipe** (#70): `fs::copy` opens a FIFO
  for reading and waits for a writer that never comes — inside a hook, the
  harness waits with it. A pipe, socket or device now fails the copy at once
  with a reason.
- **The hook probe died of SIGPIPE** (#76) when the registered command
  exited before reading its stdin — a race that failed CI once and a
  container once. The write now reports a broken pipe as "the hook did not
  read".
- Three tests read process state they did not own (#51); tree removal is
  retried before being called litter (#47); clippy 1.98 (#53).

### Known limitations

- **Under Codex an ask is a refusal.** Codex hooks can only deny at
  PreToolUse; `run` and Claude Code still prompt. Widen the allow list for
  what you run, and `termaxa report` will tell you which commands you keep
  approving. Codex's PostToolUse payload is not yet captured, so execution
  receipts — and the report's ask-outcome credit — do not exist under Codex.
- **Copilot CLI is still unverified end-to-end.** The dialect parses the
  documented format; a live capture is the next measurement.
- **Windows shells are read by shape, not by grammar** (#64). A PowerShell
  one-liner that carries `$target.Path` or an `if (...) { throw }` block
  still asks, because those segments are expressions the starter does not
  name; `cmd /c` and `powershell -Command` wrappers are not yet read the way
  `sh -c` is.
- **`wrap` is Unix-only and catches a shell resolved by name**, not
  `/bin/sh` by absolute path.
- **The integration harness runs on Unix only** (#59): the Windows job
  runs the unit tests and the new `codex_dialect` binary; the rest of the
  integration surface is `#![cfg(unix)]`.
- **Insurance copies are uncapped and never pruned** (#72), and the copy is
  not re-checked against the tree just before execution (#73).

## v0.17.0 — the authority moves

v0.16 stopped treating targets as strings. v0.17 moves **who decides**.

A daemon runs as you; the agent runs as a different user; the two talk over a
socket. The agent's account cannot read the audit log, edit the backups, change
the policy, or stop the supervisor — not because the code refuses, but because
the OS does. Eight pull requests, **441 tests on Linux, 386 on Windows**, and a
boundary rig of 23 assertions that creates a second real account and has it try.

The honest headline: **a real agent session found a bug that none of that
caught.** See below.

### Added

- **`termaxa supervise`** (Unix) — a decision daemon under the operator's user.
  In supervised mode the hook forwards the raw payload and prints what comes
  back; it does not evaluate, insure, audit or preview on its own authority,
  because anything it concluded would be a conclusion reached inside the
  agent's trust domain.
- **`termaxa init --supervised`** — prints the setup and runs none of it.
  Creating a user and chowning a directory tree need root, and a tool that asks
  for root to set things up for you is asking to be trusted with exactly the
  authority this mode exists to bound. `termaxa doctor` then reports what those
  commands actually produced, including whether the state directory is `0711`.
- **A privilege boundary rig** (`tests/boundary/rig.sh`, blocking in CI) — 23
  assertions run against a real second account, each with a **control leg**
  proving the operator *can* do the thing, so a refusal means "blocked" rather
  than "impossible for everyone".
- **`docs/supervisor.md`** and a published [field
  report](docs/field-reports/2026-08-17-supervised-routing.md).

### Changed

- **State files are private at creation**, not hardened afterwards. A daemon
  runs for hours and the interesting files are the ones it writes *during* that
  time: a log line appended mid-session inherited the process umask, and a
  backup inherited the **source file's** mode, so insuring a world-readable file
  produced a world-readable copy. Applied in basic mode too.
- **The endpoint is told, not inferred from `$HOME`.** State discovery and IPC
  discovery are now separate concepts — see the bug below.
- **`hook::run` split into `decide()` plus a thin I/O wrapper**, so the daemon
  and the one-shot hook share one decision path rather than two engines on one
  question.
- **The root rule names the root.** `match: "rm -rf /*"` is a wildcard: it
  matched every absolute path and then explained itself as "delete from root".
  A real agent was correctly stopped from deleting a `.git` directory and told
  the reason was the filesystem root. Narrowed; every case still denies.

### Fixed

- **Supervised mode did not route.** The first real agent session found that a
  hook running as the agent resolved the socket path from *its own* `$HOME`,
  found nothing, concluded basic mode, and decided on its own authority —
  writing an audit log the agent owned. The boundary was intact throughout: 18
  rig assertions passed in that same session. **The walls held; the door led
  nowhere.**

  439 unit tests, three green CI platforms and synthetic end-to-end tests were
  all consistent with a working system, because every one of them ran the hook
  and the supervisor as the same user. The rig now asserts routing across two
  real UIDs, which is the test that was missing.
- **`gate_file_write` called `process::exit(2)`.** Under the daemon, the first
  protected-file write an agent attempted would have killed the supervisor —
  and a dead supervisor denies everything afterwards.

### Known limitations

- **Unix only.** Windows has neither Unix domain sockets nor a second user
  account in the form this depends on; basic mode is the Windows answer and is
  fully supported.
- **This is not isolation.** Supervised mode moves who decides and who holds the
  record. The interception boundary is exactly where it was: an agent's native
  file tools bypass a supervised gate precisely as they bypass a basic one, and
  `wrap` catches a shell resolved by name, not `/bin/sh` by absolute path.
- **Credentials are a tradeoff, not a solved problem.** The agent account has
  none of your git, SSH or registry access. Shared HOME dilutes the boundary;
  copied credentials create rotation debt; curated-per-launch is most honest and
  most friction. Claude Code *does* authenticate cleanly as a second user — one
  OAuth round-trip, verified.
- **`SO_PEERCRED` on macOS** returns no UID rather than guessing at an untested
  `LOCAL_PEERCRED` ABI. An absent identity is recorded as absent.
- **Daemon lifecycle** is `termaxa supervise &`. systemd units and launchd
  plists are recipes to write, not managed for you.

## v0.16.0 — targets are things, not strings

v0.15 stopped treating **commands** as strings. v0.16 stops treating three more
things as text: **targets** (decide on the resolved path, not the spelling),
**the grammar** (one scanner; the labelled duplicate deleted), and **the
record** (a hash chain that says what it can prove).

Seventeen commits, thirteen pull requests. **436 tests on Linux, 384 on
Windows** — quote both figures or neither; four integration files are
`#![cfg(unix)]` and run zero tests there.

### Security

- **An escaped quote could bypass anchored deny rules — v0.7.0 through
  v0.15.0.** `echo \" ; terraform destroy -auto-approve` collapsed into a
  single segment, because the escaped quote opened a quote state and the `;`
  never split. A prefix-anchored rule (`terraform destroy*`) then never saw a
  segment starting with `terraform`, and the line matched `echo *` instead.
  Two of three tested cases resolved to a **silent allow** — no prompt, nothing
  for a human to intercept.

  Affected versions verified by compiling v0.7.0's splitter and reproducing the
  single-segment result. Fixed here: escapes outside single quotes are literal,
  as a shell reads them. **If you are on any release before v0.16.0, upgrade.**
  Advisory to follow.

### Added

- **`match_path:` rules match a command's RESOLVED targets**, not its spelling.
  `> .env` and `> ./.env` are one file rather than two strings, and no number
  of added string patterns could have achieved that — the next spelling is
  always one edit away. Path patterns match component by component, so
  `*/.env` catches a bare `.env`, a nested one, and `C:\proj\.env` alike, and
  does not catch `prod.env` or `.env.sample`.
- **A rule needs at least one matcher, and neither is mandatory.** `match:`,
  `match_path:`, or both. Enforced at parse time, because a rule with no
  matcher can never fire — a policy that says nothing while looking like it
  says something.
- **Overwrite previews.** A write now reports what the file loses before it
  happens, the way deletes have since v0.13:

  ```
  overwrite impact
    target      : /proj/config.json
    loses       : 38 B of existing content
    insurance   : copy 1 path(s) to .termaxa/backups before they are overwritten
  ```

- **`cp`, `mv`, `tee` and `dd` destinations are extracted**, each by its own
  argument grammar, and every target carries the role the command gives it:
  a copy's source is **read**, its destination **written**, and a move's source
  is **removed**. `cp a b c dir/` has three sources and one destination; a
  guess at "the last path-looking argument" would have reported `b` as at risk.
- **A hash-chained audit log (#13).** Each entry carries the hash of the one
  before it, so an edited or removed entry is detectable. `doctor` reports what
  it can verify and says so precisely — `chain valid: entries 3-5`, `2 earlier
  entries are pre-chain`, `audit chain broken at entry 4`. **Read SECURITY.md
  before treating this as a security boundary:** in basic mode it is
  tamper-evident, not tamper-resistant.
- **Provenance in the audit record:** `actor` (which harness produced the
  event) and `decided_by` (default, rule, or context). A silent default-allow
  is now a join of fields that already exist rather than a field of its own.
- **`termaxa wrap -- <agent>`** (Unix): every command the agent runs *through a
  shell* passes through the gate, hook or no hook. Shim directory, `PATH`,
  `SHELL` — not process interception, and the residue is stated: a caller
  naming `/bin/sh` by absolute path, or exec'ing a binary directly, does not
  pass through anything.
- **Mode detection and deny-on-unreachable.** When a supervisor socket exists
  and nothing answers, the hook **denies** with a reason naming the condition.
  A gate that loses its brain does not fail open.

### Changed

- **Path resolution takes an explicit cwd.** A hook runs in whatever directory
  the harness spawned it in, which is not the directory the agent's command
  runs in, so a relative target resolved against the process cwd found nothing
  and took no backup — silently, because "no such file" and "nothing to insure"
  are the same answer (#15). The ambient fallback is deleted rather than
  deprecated: with every call site threaded, the compiler reported the old form
  as dead code, which is the proof nothing resolves ambiently any more.
- **One scanner for one grammar.** Segments and their redirect targets come
  from the same walk; `shell::redirect_targets` is deleted. Comparing the two
  walks before removing one surfaced both the escaped-quote bypass above and a
  second disagreement: `>|` was split at its `|`, so the clobber was invisible
  to intent and policy while backup, re-scanning the raw string, insured it.
- **One answer to "what command is this?"** The classifier, the delete
  extractor and the insurance layer share one head resolution, so `sudo rm`,
  `/bin/rm`, `env rm`, `doas rm` and `C:\Windows\System32\del.exe` are
  classified and insured alike. Every one of those was previously classified as
  **nothing** — no intent, no breaker pressure. `git clean --force` counts too:
  one flag, two spellings, one meaning.
- **Uninsurability escalates an existing concern to deny, and never creates
  one.** An `ask` that a rule or a context signal chose, on a command nothing
  can recover, becomes a refusal. An unmatched command under a `default: ask`
  policy does **not** — `rm -rf node_modules` exceeds the copy budget and is
  routine, and a gate that denies routine work gets uninstalled.
- **The reason line names what happens to the target**: `(written)` for a copy,
  `(removed)` for a move.
- **Clippy is blocking in CI** (`-D warnings`).

### Fixed

- **`is_inside` reported not-yet-created targets as outside the project** when
  any ancestor was a symlink — which macOS `/tmp` and `/var` are. `canonicalize`
  fails on a path that does not exist, so the root canonicalized and the child
  did not, and the two were compared in different forms. Affected the
  outside-the-project warning in every prior release.
- **`backup::plan` and `backup::take` disagreed about overwrites** since v0.15:
  `take` insured them, `plan` had no overwrite branch, so every preview of a
  truncating redirect said "NOT recoverable" while the backup was in fact taken.
- **An `ask` with no interactive stdin said "declined"** when nobody had
  declined. It now names the condition and still refuses.
- **A `.env` path rule denied ordinary reads.** The rule carried a string
  pattern purely to satisfy the schema, and that pattern fired on its own:
  `cat .env`, `grep KEY .env`, even `vim .env.sample` were denied. Reading a
  file destroys nothing.

### Known limitations

- The target machinery is only as wide as its extractors. `truncate`, `xcopy`,
  `robocopy` and any other command that destroys a file by a route without a
  grammar produce no targets and reach their ordinary verdict.
- `termaxa wrap` is Unix-only, and catches a shell resolved by name. Absolute
  paths and direct `execve` are outside what a `PATH` shim can reach.
- Four integration files remain `#![cfg(unix)]`, so 32 tests — including all
  the hook-dialect ones — do not run on Windows.

## v0.15.0 — stop treating commands as strings

### Changed

- **Stop treating commands as strings.** Four of the five changes in this
  release are the same bug: matching text where we mean to match a thing.
  Policy rules now evaluate every command in three readings — as written,
  tokenized (quotes gone), and tokenized case-preserved — and the most severe
  verdict governs, so `"rm" -rf /` and `rm -r''f /` can no longer slip a deny
  by quoting. Case sensitivity is an explicit `case_sensitive: true` rule
  field, never inferred from spelling; the starter policy opts in exactly
  once, on `git branch*-D*`, which can finally mean `-D`. Reported by
  **Tim Schipper**.

  Stated behavior change: a quoted spelling of an excepted command
  (`"cat" .termaxa/policy.yaml`) now fails closed where the plain spelling
  still allows — the same call the v0.14.2 self-defence rules made for
  unlisted reads.

- **Destruction by overwrite, the redirect half.** `>` truncates, and until
  now the operator was lexed and discarded: `cat /dev/null > .env` matched
  the read-only `cat *` rule and was allowed. Truncating redirects are now
  extracted (sinks like `/dev/null` excluded), classified `file-overwrite`,
  insured by copying the target aside before execution, and denied outright
  for paths whose loss is not recoverable from the repo (`.env`, `/etc/`,
  SSH keys). The overwrite denies sit above the `.termaxa` read exceptions,
  which would otherwise launder them. The breaker counts an overwrite only
  when a rule objected, so redirected build logs never accumulate toward a
  trip. **#12 stays open**: `cp`/`mv`/`tee`/`dd` destinations are not
  covered, so the incident that opened it is not closed by this release.

- **`doctor` proves the hook fires instead of grepping for its name.** The
  old check was a substring search over settings.json; a hook whose path was
  mangled at exec failed non-blocking and doctor said "configured" in green
  through two ungated sessions (observed on Windows, 2026-08-13). `doctor`
  now invokes the registered command through the shell with a synthetic
  must-deny payload and a two-second timeout, and reports configured-and-live,
  registered-but-not-firing, or absent. The probe runs only binaries named
  termaxa (settings files arrive in cloned repos), writes no state — proven
  against the real binary, with a control — and a live hook that does not
  deny the probe is flagged rather than failed. Live means "answered when
  doctor invoked it"; pair it with the log-recency check for the
  harness-side failures the probe cannot see.

- **Decline rather than allow.** Where the policy merely fails to object —
  the default path, not an explicit `allow` rule — the hook now emits no
  decision instead of asserting an approval it never formed. Gated to the
  dialects whose contract documents that silence means no opinion (Claude
  Code, Codex); Cursor and Copilot keep receiving explicit answers until a
  live capture says otherwise. Suggested by **Tim Schipper**.

- **The recoverability invariant.** A destructive rule may be `ask` only if
  something can undo it; `ask` under an auto-approving UI is `allow`. Every
  `ask` in the starter policy now carries a documented recovery path,
  enforced by a test, and the three that had none — `docker system prune`,
  `dd` onto a raw device, `mkfs` — are denies.

### Added

- **A write-tool matcher, so a shell deny cannot be routed around one tool over.**
  Contributed by **Tim Schipper** ([@AraneaDev](https://github.com/AraneaDev)),
  closing the half of his finding 1 that v0.14.2 left open.

  The self-defence rules added in v0.14.2 are shell rules, and an agent's
  file-writing tool produces no command for them to match. So an agent that hit
  the `rm -rf` deny on `.termaxa/policy.yaml` could reach for `Write` and get
  there anyway, without evading anything: routing around an obstacle is the most
  ordinary thing an agent does. By the decision rule in `SECURITY.md` that makes
  it a bug rather than a documented limit.

  `termaxa init` now registers a second `PreToolUse` entry with the matcher
  `Write|Edit|MultiEdit|NotebookEdit`. It reads the target path and nothing
  else, and denies a write that lands in `.termaxa/` or an agent hook config.

  Two properties worth stating, because both were deliberate:

  - **It does not gate file writes.** A path it does not recognise gets no
    decision at all, not an `allow`. Asserting `allow` on every file an agent
    writes would be Termaxa answering a question it has no way to form an
    opinion about, and at the harness boundary an `allow` is an answer rather
    than a shrug.
  - **The decision does not consult the policy.** It holds in a project with no
    `.termaxa/` and one whose policy will not parse, which are exactly the
    states where the shell path has nothing to say.

  Running `termaxa init --claude-code` again adds the new entry next to the
  existing `Bash` one; the idempotence check is keyed on the matcher, so an
  install that predates this release is upgraded rather than read as complete.

## v0.14.2 — the preview no longer runs anything on a denied command

Second review round from **Tim Schipper** ([@AraneaDev](https://github.com/AraneaDev)), who this time stopped reviewing and started attacking: 22 commands against the v0.14.1 starter policy, each destructive or gate-disabling. His first PR to this repo is in this release.

### Fixed

- **A denied command could still cause a subprocess.** (GHSA-m854-p747-v3gw; see also GHSA-gxg4-5fmj-534m, which was the first instance of this same structure.) `hook::run` generates the preview before returning the
  decision, so a DENIED `terraform destroy` still ran `terraform plan -destroy`
  in the agent's working directory.

  `terraform plan` re-evaluates `data` sources against existing state, and the
  `external` data source executes an arbitrary program named in the user's
  configuration. Confirmed end-to-end against Terraform 1.9.8: a command
  Termaxa denied executed the program, and no longer does.

  v0.14.1 fixed what the Postgres preview did with the arguments it was handed.
  That was the instance; this is the class.

  The fix is not to skip the preview on deny. The denial message is more useful
  with it, and the delete preview never spawned anything in the first place.
  "May this execute?" is now an argument to `preview::generate`, decided by the
  caller that already knows the verdict. A denied `DROP TABLE` still reports
  `| DROP users` — it just no longer connects to the database it was blocked
  from. `git push` previews, being entirely subprocess-derived, are absent on a
  deny.

- **The gate now defends its own configuration** (#16, by Tim Schipper). The
  starter policy had no rule about `.termaxa/` or the agent hook configs, so
  `echo 'default: allow' > .termaxa/policy.yaml` matched `echo *` and was
  allowed — one line replacing the policy with a permissive one. A cleanup
  script hits this without any intent to evade. Adds a self-defence block, with
  read-only exceptions narrow enough to keep the documented "policy is in-repo,
  reviewable in PRs" workflow: `git diff`/`add`/`log`/`show`, `cat`, and `cp`
  anchored so the copy only goes *out* of the directory.

- **Policy fingerprinting** (#16). `termaxa init` records a SHA-256 of the
  policy; `termaxa doctor` reports it and says whether it changed. What cannot
  be blocked can at least be noticed — an agent's file-writing tools never
  reach the hook, which registers with a `Bash` matcher. The baseline lives in
  the state dir, not in `.termaxa/`, because a baseline inside the directory it
  protects is erased by the same clobber it exists to catch.

- **`ls*` and `grep*` were prefixes, not commands** (#16). `ls*` also matched
  `lsof`, `lsblk` and `lsattr`; `grep*` matched `grepdiff`. Now `ls`, `ls *`
  and `grep *`, matching what `cat *` and `echo *` already did.

- **`rm --no-preserve-root -rf /`** (#16). The `rm -rf /*` rule is named for the
  command everyone quotes, but GNU `rm` refuses that one — `--no-preserve-root`
  is the spelling it obeys, and it does not contain the substring `rm -rf`.

- **`git push origin +main`** (#16). A leading `+` on a refspec is a force push
  and has no other meaning. The classifier now counts it, so the breaker sees
  it.

- **A latent race in the `paths` tests** (#17, by Tim Schipper). `TERMAXA_HOME`
  and the process cwd are per-process while cargo runs tests as threads in one
  process; three tests mutated them and deleted the trees they pointed at. It
  surfaced as a macOS-only CI failure after #16 changed the scheduling, and had
  been latent since those tests were written. The quieter half: the tests had
  been resolving into the developer's real `~/.termaxa` on every green run.

- **Test isolation is now a helper rather than a discipline** (#18, by Tim
  Schipper). `TestEnv` takes the lock, points `TERMAXA_HOME` at a tree it alone
  owns, and on drop restores the cwd and the variable, removes the tree, and
  **fails the test if state landed anywhere else**. That last check is the
  point: `resolve_from_uses_explicit_dir_not_process_cwd` asserts nothing about
  home and would have passed while polluting — the guard catches it alone.
  Verified by breaking both claims rather than reading them.

### Documentation

- SECURITY.md gains the self-defence limitation, stated plainly: these rules are
  a string filter over the command line, not a guard on a path. `git commit -am`
  commits a modified policy without naming the file.

### Not fixed, deliberately

Matching on the tokenized form (which would also recover case-sensitivity for
`-D` vs `-d`), and carrying the redirect target out of `split_segments`. Both
retire classes rather than instances and are the v0.15 work; the second is #14,
with #12 as the other half of the same category. Wiring the intent classifier
into the allow→ask ladder is a behaviour change across every policy and is
filed with them.

## v0.14.1 — security patch: the preview could execute the command

An unsolicited end-to-end code review by **Tim Schipper** ([@AraneaDev](https://github.com/AraneaDev)) — who compiled Termaxa's own functions into a standalone harness rather than arguing from a reading — found ten issues in v0.14.0. This release fixes the ones that fail in the quiet direction. **Anyone using the Postgres preview against a real database should upgrade.**

### Fixed

- **The Postgres preview executed the user's SQL file.** (CVE-class: unintended
  code execution in a safety tool.) `pg::introspect` copied the user's argv and
  stripped only `-c`. psql honours `-f` and `-c` in the same invocation, so
  `psql -d shop -f wipe.sql -c "DROP TABLE users"` made the *preview* run
  `wipe.sql`. `hook::run` generates the preview before returning a decision, so
  this happened on commands Termaxa then **denied** — the gate performed the
  damage it had just blocked. Confirmed end-to-end against a live database.

  The fix is not "also strip `-f`": a denylist loses. `-o` truncates an
  arbitrary file, `-L` writes one, `-W` blocks on a password prompt, and the
  attached form `-cSQL` slipped past an equality check on `-c` and re-executed
  the destructive statement itself. The invocation is now **rebuilt from an
  allowlist** of connection parameters (`-h/-p/-U/-d` plus a positional
  dbname), so nothing unrecognised can reach the child process. `-w` is forced
  so a preview can never hang on a prompt, and the catalog query runs under
  `default_transaction_read_only`.

- **A harmless psql flag silently voided insurance.** The same argv was passed
  to `pg_dump`, whose flag namespace disagrees with psql's: psql's `-t`
  (tuples-only) is pg_dump's `--table`, and `-X`, `-A`, `-1` are not pg_dump
  options at all. pg_dump exited non-zero, `backup::take` returned `Err`, and
  `hook` ignores `Err` — so `psql -X -d shop -c "TRUNCATE users"` got **no
  backup** while the identical command without `-X` got one. Same shape as the
  v0.14.0 bug where path *syntax* decided whether a backup existed. The restore
  path had the same passthrough, and indexed `conn[0]` on a possibly-empty
  array; it now derives its connection from the original command through the
  same allowlist, which also makes pre-0.14.1 backup records safe to restore.

- **The trench-coat bypass reopened on a single `&`.** `shell::split_segments`
  treated `&&` as a separator but not a lone `&`, so `git status & rm -rf /`
  stayed one segment, matched the starter policy's `git status*` rule, and was
  **allowed**. The original reasoning — that `2>&1` is more common than
  backgrounding — was true but answered the wrong question: an allow rule only
  has to be wrong once. Redirection forms (`2>&1`, `>&2`, `<&-`, `&>log`) are
  now excluded by shape instead.

- **One splitter, not two.** `intent.rs` carried its own copy that split on a
  lone `&` but not on newlines, while `shell.rs` did the reverse. So
  `git status & rm -rf /` was classified correctly and allowed anyway, and
  `"git status\nrm -rf /"` was denied by policy but invisible to the circuit
  breaker's counter. `intent` now calls `shell::split_segments`. Two parsers
  for one grammar is the failure `delete::command_head` was introduced to end.

- **`delete::short()` panicked on non-ASCII paths.** `&p[p.len() - 39..]`
  byte-sliced a filesystem path, so the cut could land inside a multi-byte
  codepoint — 22 of 207 realistic Cyrillic, CJK and Latin-1 paths in
  Schipper's sweep. It is reachable from `preview_for` → `preview::generate` →
  `hook::run`, so it fired *inside the gate*, on exactly the non-ASCII Windows
  profile the module was written for. A panicking hook is an ungated agent.

- **Starter policy ordering.** Read-only allows sat above the destructive
  denies, and matching is first-wins, so `git branch -D main` matched
  `git branch*` → **allow**, and `echo $(rm -rf /)` matched `echo *` before
  `*rm -rf*` could see it. Hard stops now come first; put your own exceptions
  above the deny you want them to override. `git branch -d/-D` is now an
  explicit `ask` (matching is case-insensitive, so a rule cannot separate the
  two — the action is chosen for the safer one).

- **`examples/policy.yaml` was materially weaker than what `init` writes** —
  28 rules against 44, missing every broad delete deny and the whole
  `circuit_breaker` block, with nothing to signal it was thinner. It is now
  generated from `STARTER_POLICY`, and a test fails the build if they drift.

### Documentation

Four claims that were false, all under headings asserting the opposite:

- `SECURITY.md` said "a preview never executes the analyzed statement." From
  v0.6.1 to v0.14.0 it could. The correction now sits in the file, dated.
- `SECURITY.md` said `/bin/rm` is not insured. Since v0.14.0 it is — the
  *classifier* is what misses it. The two engines' actual boundary is now
  stated.
- The README report sample's risk line read `Medium (... = 9)` while its own
  counts give 13, which is the High band — under a heading claiming every line
  is a fact with a source.
- The README's "Top projects" cannot be produced: state is per-project and
  `report::run` reads one state dir, so those are subdirectories of a single
  project. Renamed to "Top directories" in the output and the sample.
- README line count corrected (~5,500 → ~7,200).

### Upgrade note — existing projects keep the old policy

`termaxa init` writes `.termaxa/policy.yaml` once and never rewrites it, so
**upgrading the binary does not reorder an existing project's policy.** The
starter-policy fix above reaches new projects only. To pick it up in a project
you already have, diff your policy against the new starter and move the
destructive denies above the read-only allows:

```
termaxa init            # in an empty directory, to see the new ordering
```

Then reorder your own file, or delete `.termaxa/policy.yaml` and re-run `init`
if you have not customised it. Check the result with:

```
termaxa check "git branch -D main"      # expect ask, not allow
termaxa check "echo \$(rm -rf /)"        # expect deny, not allow
```

The code fixes (psql, `&`, `short()`) need no action — they ship with the
binary.

### Still open from the same review

Filed rather than fixed, because they need design rather than a patch: the
process-cwd leak into every engine except policy resolution (#15), output
redirection modelled nowhere so `cat /dev/null > .env` is still allowed (#14),
compound commands insuring only the first segment, `notify` posting command
text unredacted, and intent classification keyed on the raw first token.

## v0.14.0 — what a delete actually costs

Every other preview engine answers "what will this destroy?" with a real
number — commits lost, rows affected, resources destroyed. Deletes were the
gap: the most common destructive command produced no preview at all. This
release closes it, and in doing so uncovered two insurance bugs that had been
live for three versions.

### Added
- **Delete blast radius.** `rm`, `Remove-Item`, `del`, `rmdir`, `rd` and
  `unlink` now produce an impact preview before the decision:
  - the **resolved** target, including Git Bash (`/c/...`), WSL
    (`/mnt/c/...`), `~` and relative forms
  - whether it falls **outside the project root**, resolves to a **user
    profile**, or is a **filesystem root**
  - **sensitive children** one level deep — `.ssh`, `.aws`, `.gnupg`, `.env`,
    `.kube`, `id_rsa`, `.npmrc` and similar
  - a **recursive file count**, budgeted at 5,000 files or 300ms, whichever
    comes first. A capped count says it was capped: "5,000+" is never
    reported as "5,000".
  - whether the operation is **insurable**, and if not, which of the two
    reasons applies

  The preview flows into the agent's own confirmation prompt, so the person
  approving sees the consequence rather than just the command string.

### Fixed
- **Path syntax decided whether a backup existed.**
  `rm -rf C:\Users\x\Desktop` was fully insured;
  `rm -rf /c/Users/x/Desktop` — the identical target — silently got no
  backup at all, because the backup planner built paths from the raw token
  and the Git Bash form failed an existence check on Windows. Agents on
  Windows emit that form routinely, so this was the case where insurance
  mattered most and quietly wasn't there.
- **PowerShell and cmd deletes were never insured.** The backup planner
  matched only `rm`, so `Remove-Item`, `del`, `rmdir` and `rd` ran without a
  backup even though the classifier and policy had gated them since v0.11.
- The delete preview and the backup planner now share one implementation of
  target extraction, path resolution and flag parsing, so the two engines
  cannot disagree about what a command targets.

### Notes
- Insurance messages now name which fact is true — "too large to copy
  (5,000+ files)" versus "no backup covers this command". They are different
  situations and the ambiguous phrasing was hiding the bug above.
- Flag syntax is resolved per shell rather than by string shape: `/s` is a
  cmd switch and `/c` is a drive root, and a shape-based guess drops
  `rm -rf /c` — a whole-drive delete.
- **What this does NOT do:** it cannot know what you *meant*. Nothing here
  would have detected that a path contained a typo. It reports what the path
  contains; the gap between intent and contents is the thing being made
  visible.
  
## v0.13.0 — the first sixty seconds

Activation release: what a developer sees between `cargo install` and their
first intercepted command.

### Added
- **Welcome screen.** Bare `termaxa` now prints five lines and one runnable
  command instead of clap's help wall. The challenge (`termaxa check "rm -rf /"`)
  works with zero setup.
- **`termaxa doctor`.** Is the gate actually wired up? Reports binary, policy,
  which agents are detected and whether their hooks are configured, which
  preview tools are on PATH, and state — ending with a numbered fix list.
  Reports "configured", never "will fire": if an agent is wired but no hook
  entries exist, it says so and points at `TERMAXA_HOOK_DEBUG`, which is the
  diagnostic that would have caught the Cursor 3.11 silent-ungating in minutes.
  Read-only by construction (see below).
- **Colour across `check`, `report`, `log`, `stats`, and `backups`** —
  dependency-free ANSI behind a gate that respects `NO_COLOR`,
  `TERMAXA_NO_COLOR`, `CLICOLOR_FORCE`, and real TTY detection on Unix
  *and* Windows.

### Fixed
- `termaxa log` rendered post-execution receipts with the ✗ (denied) mark —
  the same bug fixed in `report` in v0.12, now sharing one implementation so
  every surface agrees.
- Column alignment when labels are colourised (padding counted escape bytes,
  producing `commandrm -rf /`). Found by live testing; pinned by a test that
  strips ANSI before asserting.
- Windows TTY detection: redirected output no longer contains escape
  sequences.

### Changed
- `paths::resolve_readonly` — a diagnostic must observe, never mutate.
  `termaxa doctor` no longer creates the state directories it reports on, and
  cannot trigger legacy migration.

### Notes
- No new dependencies. Colour is raw ANSI; Windows TTY detection is two FFI
  declarations rather than a crate.
- On Windows PowerShell 5.1, `>` redirection writes UTF-16 and mangles
  Unicode glyphs. That's the shell, not Termaxa — use PowerShell 7, or
  `termaxa report --md | Out-File -Encoding utf8 report.md`.

## v0.12.0 — the flight recorder

`termaxa report` becomes the answer to "what actually happened while my agent
was working?" — one command, no flags needed.

### Added
- **Destructive-intent breakdown.** Commands the classifier recognised,
  grouped by intent (file-delete, db-destroy, git-destructive, infra-destroy),
  with circuit-breaker trips shown as a separate line. Classified ≠ blocked,
  and the report now says so.
- **Insight.** When the breaker blocks the same intent repeatedly (≥3 in
  scope), the report names the usual causes — generated files, build
  directories, an agent retry loop — and suggests an explicit allow rule if
  the work is intentional. Diagnostic, not scolding: policy relaxation stays
  deliberate. Suggested by a reader in #4.
- **Recent events.** The last six decisions with their marks, so the report
  reads as a narrative rather than a stat block.
- **Last N days rollup.** Sessions, commands, decisions, backups, breaker
  trips, and top projects by working directory. `--days N` to change the
  window (default 30).
- Previews, backups, and rollbacks surfaced as first-class counts.

### Fixed
- Post-execution receipts rendered with the ✗ (denied) mark. An executed,
  insured command is a success; it now shows ✓.

### Notes
- Everything here is derived from the existing append-only audit log. No new
  state, no schema change, no telemetry — the report reads what Termaxa
  already wrote locally.
- Token/cost accounting is deliberately **not** included: that requires the
  agent's own transcripts, and estimating it would put an invented number in
  an audit tool. Tracked separately.

## [0.11.4] — Cursor 3.11 hook compatibility + post-execution receipts
- **Fix (important): restore gating for Cursor 3.11+.** Cursor renamed its hook
  API (`preToolUse`/`postToolUse`, `tool_name:"Shell"`); Termaxa only knew the
  older `beforeShellExecution`/`afterShellExecution` shape, so on current Cursor
  it silently stopped intercepting commands. Now handles both. Verified live on
  Cursor 3.11.25. Old Cursor, Claude Code, Codex, Copilot unchanged.
- **Post-execution receipts.** Records a receipt when a command finishes (Claude
  Code `PostToolUse` and Cursor `postToolUse`, both verified live on Windows).
  The circuit breaker excludes human-approved commands from the retry threshold,
  so approving a legitimate command no longer nudges the agent toward an auto-deny.
  `termaxa init` now registers both pre- and post-execution hooks.
  
## [0.11.3] — Report surfaces breaker trips
- `termaxa report` now shows a `breaker` line counting circuit-breaker trips
  in scope, so auto-denied retry-storms are visible in the session summary.

## [0.11.2] — Zero-setup `check`
- `termaxa check` now works with no project setup: when no `.termaxa/policy.yaml`
  exists it evaluates against the built-in starter policy (read-only "demo mode"),
  so `cargo install termaxa && termaxa check "rm -rf /"` works immediately.
  `run` and `hook` still require an explicit project policy — enforcement stays
  deliberate.

## [0.11.1] — Classifier: delete indirection
- The intent classifier now recognizes deletes hidden behind command
  indirection: `find -exec/-execdir <rm>`, `find -delete`, `xargs rm`,
  `unlink`, and `shred -u`. Closes a bypass found in live agent testing
  where `find . -exec rm -rf {} +` slipped past the circuit breaker.

## [0.11.0] — Session circuit breaker
- When the same destructive intent (file delete, DB destroy, git force-op,
  infra destroy) is asked or denied twice in one agent session, further
  variants are automatically DENIED — closing the retry-with-different-syntax
  gap found in live Cursor testing. Configurable via `circuit_breaker:` in
  policy.yaml (enabled by default, threshold 2).
- Starter policy now DENIES bulk deletes by default (Unix, PowerShell, cmd
  forms): with auto-approving agent UIs, `ask` silently degrades to `allow`.
- Audit entries carry an `intent` classification (backward compatible;
  old log lines parse unchanged).

## v0.10.5 — 2026-07-09
- Formatting cleanup (`cargo fmt`); no functional changes from v0.10.4.

## v0.10.4 — 2026-07-08
- Fixed audit-path hash mismatch that caused empty audit logs.
- Documented honest enforcement limits; removed internal build notes.
- Multi-agent hook support (Cursor, Codex, Copilot dialects) and
  `termaxa init` flags landed in this series.
- Note: version numbers v0.10.0–v0.10.3 were internal iteration
  numbers and were never published; v0.10.4 is the first release
  of the 0.10 series.
  
## [0.9.0] — Launch

### Added
- **Terraform/OpenTofu previews.** `terraform apply|destroy` (and `tofu`) run `terraform plan` first and surface `+add ~change -destroy` counts, leading with destroyed resources. Local `terraform.tfstate` is backed up before apply.
- **Execution Report** (`termaxa report`) — session summary composed from the audit trail: commands by decision, blocked list, database/infra impact (from persisted preview summaries), backups with rollback availability, and a transparent risk score (`deny×3 + escalation×2 + ask×1`). `--session`, `--all`, `--md`.
- Preview summaries now persist on audit entries, so reports state impact as recorded fact.
- `termaxa paths` — show where policy (in-repo) and state (`~/.termaxa`) live.

### Fixed
- **Broken-pipe panic**: `termaxa report --md | head` (and any piped output) now exits cleanly on Unix instead of panicking.
- `--help` leads with a clear description and worked examples.

## [0.8.0] — Home-directory state
- Logs and backups moved from in-repo `.termaxa/` to `~/.termaxa/projects/<name>-<hash>/`, so a `git reset --hard` can no longer destroy the audit trail. Automatic one-time migration of legacy in-repo state, including path-rewriting inside the backup manifest. Policy stays in-repo as reviewable policy-as-code.

## [0.7.0] — Shell-aware evaluation
- Compound commands (`&&`, `||`, `;`, `|`) are split and judged per segment; the most dangerous segment governs. Closes a bypass where `git status && <anything>` rode a `git status*` allow rule (found by the first live Claude Code session; now a named regression test). `$(...)`/backtick command substitution escalates to a human.

## [0.6.1] — Loss-aware force-push previews
- Force pushes now show what the remote will **lose** (`HEAD..@{u}`), not just what it gains. Found in live use: the preview previously said "nothing to push" while a force push destroyed a commit.

## [0.6.0] — Insurance engine
- Automatic backups before destructive operations: git remote-ref pinning, mode-aware `pg_dump` (CASCADE pulls in FK dependents), file copies for `rm`. `termaxa backups` / `termaxa rollback <id>`.

## [0.5.0] — Operability
- Session tracking from hook events; `termaxa log` filters (`--decision`, `--source`, `--json`); `termaxa stats`; `termaxa notify --test`.

## [0.4.0] — Notifications
- Slack-compatible webhook on deny/ask, fire-and-forget (never blocks a decision). Log entries show approval + exit code.

## [0.3.0] — Postgres impact analysis
- Static (`NO WHERE CLAUSE` detection) and live (row estimates from `pg_class.reltuples`, FK dependents) analysis for `DROP`/`TRUNCATE`/`DELETE`, reusing the intercepted command's own connection.

## [0.2.0] — Git previews
- `git push` previews: commits and diffstat, with new-branch handling.

## [0.1.0] — Core
- Policy engine (YAML, first-match-wins, wildcard, normalized matching), Claude Code PreToolUse hook, context signals with one-way escalation, append-only JSONL audit, `init`/`check`/`run`/`log`.
