# Supervised mode

**Unix only. Not available on Windows** — it needs Unix domain sockets and a second user account in the form this depends on. Basic mode is the Windows answer and is fully supported there; `termaxa doctor` says so rather than hinting.

**Status: proved by an automated rig across two real users, and by two real agent sessions** — the first of which found a routing bug the rig could not see, and the second of which confirmed the fix and found a wrong deny message. See [the field report](field-reports/2026-08-17-supervised-routing.md) and [What is not yet proven](#what-is-not-yet-proven), which is shorter than it was.

---

## What it changes

In basic mode — the default everywhere — the hook runs as **your own user**. It reads the policy, decides, writes the audit log and takes backups, all with the same filesystem authority the agent has. That is enough for the threat model Termaxa is built for (see [SECURITY.md](../SECURITY.md)): an agent making expensive mistakes, in the open, through the shell.

It is not enough for one specific claim. In basic mode, **the audit log is the agent's own account of itself**. Anything that can edit an entry can recompute the hash chain over it. The record is tamper-evident, not tamper-resistant.

Supervised mode moves the authority. A small daemon runs as **you**; the agent runs as a **different user**; and the two talk over a socket:

```
  agent user                          operator (you)
  ----------                          --------------
  claude ──▶ termaxa hook ──socket──▶ termaxa supervise
                                        │
                                        ├── reads the policy
                                        ├── decides
                                        ├── takes the backup
                                        └── writes the audit log
```

The hook forwards the **raw payload** and prints what comes back. It does not evaluate, insure, audit or preview on its own authority — anything it concluded would be a conclusion reached inside the agent's trust domain, which is the thing this mode exists to stop relying on.

What that buys, concretely:

| asset | basic mode | supervised mode |
|---|---|---|
| policy file | agent-writable; self-defence rules advise against it | operator-owned, `0644` — agent reads, cannot write |
| hook configs | same | same — operator-owned, read-only to the agent |
| audit log | the hook appends directly, as the agent's user | **the supervisor appends; the agent's user has no path to it** |
| backups | the hook writes them directly | **the supervisor writes and holds them; the agent cannot read, edit or delete them** |
| the supervisor | — | the agent cannot stop it |

Every row of that table is asserted by `tests/boundary/rig.sh`, which creates a real second account and has it **try**. 18 assertions, each with a control leg proving the operator *can* do the thing — so a refusal means "blocked", not "impossible for everyone".

---

## Setup

`termaxa init --supervised` prints the commands and **runs none of them**. Creating a user and chowning a directory tree need root, and a tool that asks for root to set things up for you is asking to be trusted with exactly the authority this mode exists to bound.

```bash
cd your-project
termaxa init --supervised     # prints; does not execute
```

It prints, roughly:

```bash
# 1. an account for the agent to run as
useradd --system --create-home --shell /bin/bash termaxa-agent

# 2. the policy: the agent reads it, and cannot change it
chown you:you .termaxa/policy.yaml
chmod 0644 .termaxa/policy.yaml

# 3. the state directory: traversable, not listable
chown -R you:you ~/.termaxa
chmod 0711 ~/.termaxa

# 4. run it
termaxa supervise &
sudo -u termaxa-agent termaxa wrap -- claude
```

Then:

```bash
termaxa doctor
```

which reports what those commands actually produced rather than assuming you typed them correctly.

### Why `0711` and not `0700` or `0755`

This is the one number worth understanding, because both obvious choices are wrong and neither is obviously wrong.

```
0755   the agent can LIST the state directory — and from there read the
       audit log and the backups it is supposed to be unable to reach
0700   the agent cannot traverse to the socket, so every hook invocation
       denies. Perfectly secure, completely useless.
0711   traverse without enumerate: the agent reaches a socket path it
       already knows, and cannot list the directory or anything in it
```

Traversal needs execute permission on **every** directory in the path, which is the part a design sketch does not surface. The socket lives in `~/.termaxa/run/` at `0755`, containing nothing but the socket; the state directory above it is `0711`; the log and backup directories inside are `0700` in their own right, because `0711` grants traversal and anything private must be private itself rather than hiding behind its parent.

All three of those numbers came from running the rig with a second real user, not from reasoning about them. The first two designs were plausible on paper and both failed.

---

## Failure direction: it denies

If the socket is present and the supervisor does not answer — not running, wedged, or a version mismatch — **the hook denies**, with a reason naming the cause:

```
[termaxa] supervised mode is configured but the supervisor is not answering
          — refusing rather than deciding without it
```

This is deliberate and it is the permanent answer to a real incident: Cursor 3.11 renamed its hook events, Termaxa silently stopped gating it, and four releases shipped with the gate quietly open. A gate that loses its brain must not carry on as if it had one.

The practical consequence: **if you stop the supervisor, the agent stops working.** That is the intended trade. Stop the agent first, or remove the socket to return to basic mode.

Protocol version mismatches deny too, with their own message — the hook binary and the daemon binary *will* skew during an upgrade, because nothing restarts a daemon when a package manager replaces a file.

---

## Credentials: a named tradeoff, not a solved problem

The agent account is a different user. It has none of your git config, SSH keys, npm tokens or cloud credentials. That is the point — and it is also the part most likely to make supervised mode annoying.

Three ways out, none free:

| approach | what it costs |
|---|---|
| **shared HOME** | easiest. Dilutes the boundary you just built: the agent user can now read whatever your home directory holds. |
| **copied credentials** | works. You now have two copies of every secret to rotate, and a second place they can leak from. |
| **curated per launch** | most honest, most friction. Give the agent account only the credentials the task needs — a deploy key for one repo rather than your SSH agent. |

The default recommendation is curated-per-launch, and the honest caveat is that nobody has dissolved this problem, including us. An agent that cannot push is an agent that cannot finish half its work; an agent with your full credential set is a boundary in name.

Decide deliberately, and write down what you chose.

---

## What is not yet proven

Everything above is verified by an automated rig and by end-to-end tests with synthetic payloads. **No real agent has run a real session under this topology.** Until that happens, these are the specific things nobody has watched:

- **Whether a real agent can finish real work under a separate account.** Claude Code *authenticates* cleanly as a second user — verified 2026-08-17, one OAuth round-trip, no shared HOME and no copied credentials. What is still untested is git: the agent account has no git identity or SSH key, and the first `git push` is where that bites.
- **Previews in supervised mode.** Static analysis runs supervisor-side; live introspection subprocesses (`psql`, `git`, `terraform show`) run hook-side in the agent's domain and travel as an *agent-observed annotation*, never as the gate's own observation. Where that leaves a preview thinner than in basic mode, the output is supposed to say so. Nobody has compared them side by side.
- **Latency and contention.** Every command makes a socket round-trip to a single-threaded server with a two-second timeout. An agent issuing commands rapidly may expose queuing the design assumed away.
- **`SO_PEERCRED` on macOS.** Linux reports the connecting UID. macOS spells it differently (`LOCAL_PEERCRED`, different struct), and rather than guess at an untested ABI, `peer_uid` returns `None` there — so the audit records an absent identity rather than a wrong one.
- **Daemon lifecycle.** `termaxa supervise &` is the documented start. systemd user units and launchd plists are recipes to write, not managed magic, and neither has been exercised.

When the proving run happens it will be published as a field report — including whatever it breaks. Every real bug this project has found came from running the thing rather than reasoning about it, and this document will be updated to say what changed.

---

## Returning to basic mode

Stop the supervisor and remove the socket:

```bash
pkill -f "termaxa supervise"
rm ~/.termaxa/run/supervise.sock
```

Mode is detected from the filesystem — the socket is either there or it is not — so removing it returns the hook to deciding locally. A configuration file claiming supervision would be a claim; the socket is a fact.
