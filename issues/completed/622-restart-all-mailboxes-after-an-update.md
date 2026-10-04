# #622 — Restart every mailbox on the machine after an update

## Current Behavior

Built 2026-10-04.  `restart-mailboxes.sh` in the program folder restarts
every mailbox service on its list and checks each is running again.  It
is built per machine from a tracked template, for that machine's service
manager only, and git ignores the built copy.  The installer builds it,
adds each mailbox service it sets up to the list, and at its end offers
to restart every listed mailbox.  `scripts/test-restart-mailboxes.sh`
covers it (every case passing).  This machine's copy is built for runit
and lists `kuvalu-mail` and `kuvalu-notes`.

Why it is needed: one program folder (the checkout) serves every
mailbox on a machine (#102), so updating that folder is the whole
update.  But a running daemon keeps the program it loaded when it
started, and until each mailbox's service is restarted it goes on
running the old code, with nothing saying so.  On this machine on
2026-10-04 both mailboxes had been running since 06:40, four hours
before the morning's fixes were committed.  Restarting by hand meant
remembering every mailbox's service name and the right command for this
machine's service manager.

## Intended Behavior

- **The list is a variable at the top of the script**, so each machine
  keeps its own.  Git cannot ignore single lines of a tracked file, so
  the script is not tracked.  It is built from a tracked **template**,
  `scripts/.templates/restart-mailboxes.sh`, the same pattern the
  documents use (`docs/.templates/` expanded into `docs/`).  The built
  copy is listed in `.gitignore`.
- **The template holds one restart method per service manager** —
  runit, systemd (user or system), OpenRC, NixOS — each a folded block
  with its own closing marker.  The built script keeps only the block
  for this machine's manager.
- **Running it:**
  - with no arguments, it restarts every listed service;
  - names given as arguments are restarted instead, that run only, and
    the list is not changed;
  - `--add NAME` adds a name to the list if it is not already there, and
    restarts nothing;
  - `--check` says whether every listed (or given) service is
    installed, and restarts nothing.
- **An empty list and no arguments**: it asks, "Type the service name
  of each mailbox, pressing enter after each one.  When you're done,
  give a blank name (press enter twice)."  The answers are written into
  the script's own list line, then restarted.  With no terminal to ask
  on, it stops with an error instead.
- **Before restarting anything** it checks every name is an installed
  service of this manager.  An unknown name stops the run before any
  restart, and names the service that was not found.  It does not guess
  at a near match.
- **After restarting** it waits three seconds (a daemon that dies on
  startup usually does so by then), asks the manager whether each
  service is running, and exits non-zero if any is not.
- **Root**: runit, OpenRC, NixOS and systemd system services need root
  to restart; those commands go through `sudo` when not already root.
  systemd user services need no root.
- **The installer** (owner's choice of "update script", 2026-10-04:
  re-running the installer is how rmail is updated today):
  - builds the script if it does not exist, and keeps an existing one;
  - adds the service it just set up with `--add` (owner, 2026-10-04:
    "yep"), so a machine set up by the installer never has an empty
    list;
  - at its very end, runs `--check`; if every listed service is
    installed, asks "Restart every listed mailbox now, so each runs this
    version? (uses sudo)" and restarts on yes.  It asks rather than
    restarting unasked because the installer otherwise never escalates
    privileges.  `--restart-mailboxes` / `--no-restart-mailboxes`
    answer in advance, and `--yes` says yes.  When a listed service is
    not installed yet — on runit, OpenRC, NixOS and systemd system
    services the owner installs a newly written service by running
    printed commands — it says so and what to run afterwards, and does
    not treat it as an error.

## Suggested Implementation Steps

1. `scripts/.templates/restart-mailboxes.sh`: the template.  At the
   top, the program folder (`DIR`, filled in when built, overridable
   with `--dir=PATH`), the list `MAILBOX_SERVICES` (a space-separated
   string, empty) and `SERVICE_MANAGER`.  Then one block per manager —
   `# {{{ manager: X` to `# }}} manager: X` — each defining the same
   three operations: is this service installed, restart it, is it
   running.  The systemd block looks up per name whether it is a user
   or system service and picks the operation from a table by that
   answer.  Then the shared part: options, the prompt, writing the list
   back, checking, restarting, reporting.  The list is written back by
   writing a new file beside the script and moving it over, never by
   editing in place, because the shell is still reading the script as
   it runs.  `SVDIR` and `INITD` can point elsewhere (the tests use
   that); `RMAIL_RESTART_SETTLE` shortens the wait for the tests.
2. `scripts/make-restart-script.sh <manager> [DIR]`: builds
   `<DIR>/restart-mailboxes.sh` from the template, keeping only the
   block for `<manager>` and filling in the folder and manager.  The
   managers it accepts are read from the template's block markers.
   Checks the result has exactly one block, no unfilled placeholder,
   and parses, before it replaces anything.  Keeps an existing built
   script unless given `--force`.
3. `scripts/install.sh`: in the service step, records whether a service
   was set up; once the manager is known, calls the builder, then
   `--add` for a service set up this run.  At the very end, the restart
   step described above, with `restart_mailboxes` in the yes/no option
   keys and the help text.
4. `.gitignore`: `/restart-mailboxes.sh`.
5. `scripts/test-restart-mailboxes.sh`: builds the script into a
   scratch folder for each manager, with stand-in `sv`, `systemctl`,
   `rc-service` and `sudo` commands on the path that record what they
   were asked to do.  Checks: one manager's block kept; an unknown
   manager refused; an existing built script kept, `--force` replacing
   it; the list restarted through sudo; arguments overriding the list
   without changing it; an unknown name stopping the run before any
   restart; a service that stays down failing the run; `--add` adding
   each name once and refusing a bad one; `--check` passing and
   failing; the empty list refused with no terminal and asked for on
   one (through `script`), the answers saved and the file still
   parsing; systemd user services without sudo and system ones with it;
   OpenRC and NixOS through sudo.
6. `docs/.templates/service.md`: "Restarting every mailbox after an
   update".

## Related

- #102 — the mailbox is the installation (one program folder serves
  every mailbox; updating it is the update)
- #612 — service names, one per mailbox
- #614 — documents built from templates at install time (the pattern
  this follows)
