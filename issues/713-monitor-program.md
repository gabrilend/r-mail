# rmail monitor program

## Current Behavior

(Before 2026-11-05; see Status.)  No monitor exists.  Each mailbox runs alone as its own service
(#613); nothing lists the mailboxes on a machine or
their versions, except the installer's scan of existing installs when it
runs.  Since #102 a mailbox's config is the `config` file inside it (the
`~/.config/rmail/config-*` path below is from before).


## Intended Behavior

A system-level program that manages rmail instances on a machine. Think of
it as the "mailboxes" view from the Android app, but for the computer — a
platform that other things can interface with.

## Core features

### Instance detection
- Detects all running rmail instances on the system
- Shows version number, mailbox path, port, status
- Instances can opt out of detection via a config flag

### Version tracking and transition
- Caches the last known version number per instance
- When a new version is detected (higher than cached), runs a transition
  script that walks through the changes made between versions
- The transition script follows the development story one change at a time
  (from LLM transcripts), showing what was built, why, and how
- This serves as both a changelog and a "how this program was built" story
  — a selling point for someone evaluating rmail

### Platform / API design
The monitor should be designed as a platform — something other tools can
talk to. Not a rigid controller, but a capable actor with clear abilities.

Design philosophy (per the user): less "movement_controller" or
"kinematic_rigidbody" and more "seventeen.footmen" or "dave the barbarian" —
"what can I do? I can swing a sword, and I am tough as I am hard. Let me
'at em."

In other words: the API should describe what the monitor CAN DO, not what
it IS. It's an agent with capabilities, not a data model with methods.

Capabilities might include:
- "I can list all rmail instances on this machine"
- "I can tell you the version and status of each one"
- "I can show you the story of how this version was built"
- "I can restart an instance"
- "I can run a script against an instance's hooks"
- "I can relay a message between instances"

This should integrate with rmail's scripting system (hooks) as a first-class
interface — the monitor is another hook consumer/producer.

### UI
- List of instances (similar to Android mailbox list)
- Select an instance to see details and configure
- Version history browser with the development narrative
- Could be TUI (terminal), or serve a local web UI, or both

## Suggested Implementation Steps
- Detect instances: scan for running processes with `rmail.lua` in the
  command line, or scan `~/.config/rmail/config-*` files
- Version: rmail needs a `--version` flag or a version constant in the source
- Transition scripts: stored per-version in a `transitions/` directory,
  each one describing what changed and running any necessary migrations
- The monitor could be a separate Lua script or a shell script that wraps
  rmail functionality

## Status

First slice built 2026-11-05: instance detection, the opt-out, the
version number, the version cache and the story, and a capability-led
command line.

- `rmail.lua` carries `RMAIL_VERSION` (0.1.0), prints it for
  `--version`, logs it at start and writes it to `.state/version`.
- `scripts/rmail-monitor.lua` with no arguments says what it can do:
  `list` (every mailbox, running or not, with port, version and
  service; `--plain` for other programs), `tell MAILBOX`, `story [FROM
  [TO]]` and `version`.  It names what it cannot do yet: restart a
  mailbox, run a script against its hooks, relay between mailboxes.
- `transitions/0.1.0.md` is the first chapter.

Second slice built 2026-11-06 (branch `claude/713-monitor-restarts`,
stacked on `claude/713-monitor`): "I can restart an instance".

- `restart MAILBOX` restarts one mailbox, named as `tell` names it;
  `restart --behind` restarts every running mailbox whose program on
  disk carries a newer version than the one it last ran (the mailboxes
  `list` already tells "restart it to run ..."); `--dry-run` says the
  command and runs nothing.
- The command is the service manager's, as `restart-mailboxes.sh` (#622)
  runs it: `systemctl --user restart` for a user service, and through
  `sudo` when not root, `systemctl restart` (systemd, NixOS), `sv restart`
  on the folder in `SVDIR` (`/var/service`) and `rc-service NAME restart`.
- It then waits up to 20 seconds for the mailbox to run under a pid it
  did not have before, at the version on disk, and says which.  A
  refusal from the service manager, or no new daemon in time, is said and
  the command fails.
- The help lists restarting among what it can do.
- Test: `scripts/test-monitor.sh`, section "restarting", with stand-ins
  for `systemctl`, `sv`, `rc-service`, `sudo` and `id` that restart the
  test's own daemons.

Not built: running scripts against hooks, relaying, the monitor as a
hook consumer or producer, a web UI, and transition chapters that carry
migrations.

## Decisions (2026-11-05)

- **Found two ways, merged by config.**  The service files of the five
  init systems `install.sh` writes for (named `rmail` or `rmail-*`, in
  all five places whatever is running, as `install.sh`'s own scan does),
  and the processes whose command line runs `rmail.lua`, so a mailbox
  started by hand is listed too.  Not `~/.config/rmail/config-*`, which
  the suggested steps name: since #102 there is no such file, and the
  service file is what names a mailbox's config.  A process is counted
  only if the config it names can be read, so an editor open on
  `rmail.lua` is not a mailbox.
- **The opt-out is `monitor = no`** in the mailbox's config (also
  `false` or `off`).  Such a mailbox is not listed, told about or
  counted; rmail itself ignores the key.
- **Version 0.1.0, raised by hand.**  There was no version before.  It
  starts at 0.1.0 because nothing has been released, and it is compared
  part by part as numbers.  It is raised when a change is worth a
  chapter, not on every commit, so the story stays one chapter per
  version.  A commit count or date would number every change and make
  the story either empty or a log.
- **The version is read, not run.**  The monitor reads the
  `local RMAIL_VERSION = "..."` line from the program a service or
  process names, so it can tell a running daemon that it is behind the
  program on disk ("restart it to run 0.2.0") without starting anything.
  What a mailbox last ran is the daemon's own `.state/version`.
- **The cache lives in `${XDG_STATE_HOME:-~/.local/state}/rmail/monitor-versions`**,
  one line per mailbox, written only when something changed.  Not in
  the mailbox: the monitor may be run by a user who can read a system
  service's mailbox and not write to it, and what the monitor has seen
  is the monitor's own fact.
- **A new version is told, not acted on.**  The issue's transition
  script "walks through the changes ... and running any necessary
  migrations".  This slice tells: once per mailbox per new version, with
  the `story` command that shows the chapters between.  It runs nothing:
  a listing that changes someone's mail would be a surprise, and no
  change so far has needed a migration that `migrate-mailbox-layout.sh`
  does not already do.
- **Chapters are Markdown in `transitions/<version>.md`**, written in
  plain words (what was built, why, how).  The development story before
  0.1.0 stays where it is, in `issues/completed/` and `llm-transcripts/`;
  the first chapter points there rather than retelling it.
- **Capabilities are the commands.**  Following the owner's "dave the
  barbarian" direction, the help is a list of "I can ..." sentences, each
  with the word that asks for it, and an ability it lacks is named as
  one it cannot do yet rather than left out.  Something asked of it that
  it cannot do gets "I cannot ..." and the list.
- **A terminal program in Lua**, the issue's own suggestion, so it runs
  with the interpreter the checkout already has and needs no library.
  A web UI is left for later; the `--plain` output is what one would
  read.
- Test: `scripts/test-monitor.sh`.

## Decisions (2026-11-06)

Made while building the restart, to be overturned by the owner's word:

- **A mailbox started by hand is not restarted.**  The monitor knows its
  pid and its command line, but not its terminal, its environment or
  whether it was meant to keep running; stopping it and starting a copy
  in the background would be a guess, and stopping it alone would only
  stop it.  It says so and names the pid.
- **The service manager's own restart, with #622's commands.**  The
  installer already settled how each manager restarts a mailbox
  (`scripts/.templates/restart-mailboxes.sh`); the monitor uses the same
  commands, so the two never disagree about a service.  Unlike that
  script it needs no list kept by hand: the services it restarts are the
  ones it finds.
- **sudo only when not root, and only for system services.**  A systemd
  user service never needs it.  sudo asks for its password on the
  terminal as it would anywhere.
- **`--behind` restarts only running mailboxes.**  A stopped one runs the
  program on disk when it is next started, which `list` already says;
  starting it would undo the owner's having stopped it.  Naming a
  stopped mailbox to `restart` does start it, as the service managers'
  own restart does.
- **A restart counts once the mailbox runs under a new pid at the
  version on disk**, read from the `.state/version` its daemon writes at
  start, and not when the service manager returns: a service manager can
  accept a restart whose daemon then fails to start.  The wait is 20
  seconds (`RMAIL_MONITOR_RESTART_WAIT` for the tests).
- **No version raise.**  0.1.0 stays: the version is raised for a change
  worth a chapter in `transitions/`, and the monitor is not the daemon.

## Witness material

The user described the design philosophy during a late-night session on
2026-03-28. The analogy to "dave the barbarian" — a simple, capable agent
that describes itself by what it can do rather than what it is — captures
the intended API design direction. The development story (LLM transcripts
walking through each change) is both a technical changelog and a marketing
tool: "look how this was built, step by step, by a human and an AI
collaborating."
