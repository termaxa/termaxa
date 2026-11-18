# Termaxa for Claude Code

This plugin puts Termaxa's hook on every project you open in Claude Code.
Termaxa judges each shell command and file write an agent makes before it
runs, copies aside what a command would destroy, and keeps a record on your
machine.

In a project with no `.termaxa/policy.yaml`, it **watches**. The built-in
starter policy judges every call. Nothing is asked and nothing is approved,
and only the floor is refused: the gate's own files, agent hook
configuration (Claude Code's settings and plugins among them), and the hard
stops such as `rm -rf /` and `kubectl delete`. `termaxa report` shows what a
policy would have asked or refused, and `termaxa init` writes a policy,
offering rules for what asked in the record.

In a project with a policy, the policy decides, in its own mode. In a
project that registers `termaxa hook` itself, the plugin's hook steps
aside, so each command is judged once.

## Install

First install the `termaxa` binary, version 0.23.0 or later, with
Homebrew, cargo, winget or Scoop, or from a release: see
[Quick start](https://github.com/termaxa/termaxa#quick-start). Then, in
Claude Code 2.1.275 or later:

```
/plugin install termaxa --marketplace termaxa/termaxa
```

On an earlier version with plugins:

```
/plugin marketplace add termaxa/termaxa
/plugin install termaxa@termaxa
```

## What it runs, sends and fetches

- It registers one command, `termaxa hook --plugin`, for `SessionStart`,
  and for `PreToolUse` and `PostToolUse` on `Bash`, `Write`, `Edit`,
  `MultiEdit` and `NotebookEdit`. The plugin holds no program and no
  script: this file, `.claude-plugin/plugin.json` and `hooks/hooks.json`.
- `termaxa` reads what Claude Code sends the hook (the command, or the path
  a tool writes), the project's policy if there is one, and the files a
  command would change. It writes its record and its copies under
  `~/.termaxa`, or the directory `TERMAXA_HOME` names, and nothing into the
  project.
- Nothing is sent or fetched over the network, unless a project's policy
  sets a `notify` webhook, which then receives the commands it names.

Without `termaxa` on `PATH` the hook cannot run, and nothing is watched or
refused until it is installed.

## Turning it off

Disable or uninstall it yourself, with `/plugin`. An agent that runs
`claude plugin disable` or `uninstall`, or writes under `~/.claude/plugins/`,
is refused by the floor.

Termaxa: [termaxa.com](https://termaxa.com) ·
[github.com/termaxa/termaxa](https://github.com/termaxa/termaxa) ·
[how watching works](https://github.com/termaxa/termaxa/blob/main/docs/observe-mode.md#watching-a-project-that-has-no-policy)

## License

MIT OR Apache-2.0, at your option, as Termaxa itself.
