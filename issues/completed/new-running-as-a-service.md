# #new-running-as-a-service — Each mailbox runs as its own service, set up by the installer

## Status

Completed — a blueprint written 2026-10-04 (#402) for what was built
before issue files described it, drawing on #205, #381 and #382.

## Current Behavior

A mailbox is meant to be always running, so it can receive.  The
installer (#345) ends by offering to set it up as a service of the
machine's init system, which it detects: NixOS first (it runs systemd,
but its service files are rewritten on every rebuild, so it gets its own
form), then whatever runs as process 1 — systemd, runit, OpenRC — and
failing that, whichever of their tools is installed.  None found: no
service, and the README's examples are named.

| init system | what the installer writes | who installs it |
|---|---|---|
| systemd | a user service (`~/.config/systemd/user/`), or a system one | the installer, for a user service; the owner, for a system one |
| runit | `/etc/sv/<service>/run` | the owner |
| OpenRC | `/etc/init.d/<service>` | the owner |
| NixOS | `<service>.nix`, a module to import in `configuration.nix` | the owner, then `nixos-rebuild` |

The installer never raises its own privileges: where root is needed it
writes the file into the checkout and prints the commands to put it in
place.

**One mailbox, one service** (#381).  The service is named after the
mailbox (`rmail-home-ritz-mail` for `/home/ritz/mail`), or what
`--service-name` gives.  Before writing, the installer refuses a name
already taken by a service for another mailbox — with no automatic
second choice, which would only move the surprise.  Each service runs
`run-rmail.sh <mailbox>/config` (#382: the config file names the
mailbox), on the mailbox's own port.

**Logs.**  Services send the daemon's standard error to
`/tmp/<service>.log` (RAM, so a busy log never wears a disk, #205), or to
the journal on NixOS; the daemon also keeps its own copy
(#new-the-daemons-log).  `scripts/view-logs.sh` follows either.

**By hand.**  `run-rmail.sh <config>` starts a daemon in the foreground
with the bundled Lua if the installer built one, else the first system
Lua found.  `--once` makes it a visit: announce, sync, stay reachable a
minute, exit (a portable drive's way, #339).

## Intended Behavior

As above; #384 adds launchd for macOS.

## Suggested Implementation Steps

1. `scripts/install.sh`, the "SERVICE SETUP" section: detection, the
   clash check (`service_exists`), one branch per init system.
2. `run-rmail.sh`; `scripts/view-logs.sh`.
3. Tests: `scripts/test-mailbox-selection.sh` (which config a daemon
   serves; a port already held).

## Related documents

- `docs/.templates/service.md`
- `#205`, `#339`, `#345`, `#381`, `#382`, `#384`
