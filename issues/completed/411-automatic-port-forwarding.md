# #411 — Asking the router to forward the port, and warning contacts when the router allows it

## Status

Completed 2026-10-08 (second time): the daemon's start-up router check
is removed; checking the router is the installer's job.  Test:
`scripts/test-router-left-alone.sh`.

Reopened 2026-10-08.  Completed before as a blueprint written 2026-10-04
(#621) for what was built before issue files described it; #412, #413
and #414 refine it.  Reopened because the owner, on learning that the
security check probes the router at every start whether asked to or not:

> "We shouldn't open any ports automatically unless specifically
> requested to. Also we shouldn't probe the network unless requested, and
> even then I highly don't recommend it, and instead highly suggest that
> users handle wiring things up correctly themselves."

Found from the W client project (`/mnt/mtwo/games/azeroth-core/custom-client`),
whose own mailbox could not be started without touching the router; its
test starts rmail with a program path missing `upnpc` and `natpmpc` to
keep it away (`tests/052-test-note-box-frame.sh --real-mailbox`).  That
alone does not keep it away: the daemon looks for both programs in its
own `deps/bin/` before the program path, and the installer may have built
`natpmpc` there (found by the W client session, 2026-10-08).

The owner settled where the check belongs, 2026-10-08:

> "we should not enable UPnP functionality. It's up to the user to verify
> that functionality is off when they install rmail, which will do the
> probing test. But we don't want to do it on startup."

and that contacts warned by an earlier run are told nothing more.

## Current Behavior

A mailbox behind a home router can only be reached if the router
forwards its port to this machine.  Two router protocols let a program
ask for that without the owner opening the router's settings: **UPnP**
and **NAT-PMP**.  The daemon uses them through the `upnpc` and `natpmpc`
programs, found in `deps/bin/` and then anywhere on the program path.

**Asking** — only with `auto_port_forward = true` in the config, after
the port is claimed (#101): UPnP first, then
NAT-PMP (an hour's lease); the mapping is recorded in
`.state/nat_mapping.json` and renewed every 30 minutes; at start-up a
mapping left by an earlier run is removed first.  Failure is a warning:
the port may still be forwarded by hand.  Off by default: rmail does not
enable UPnP functionality on its own.

**Removing an old opening** — at start-up, `nat.cleanup_old_mapping`
removes a mapping this mailbox recorded in `.state/nat_mapping.json`,
whatever `auto_port_forward` now says.  With nothing recorded it runs no
router program.

**No check at start-up.**  The daemon does not probe the router.  The
security check that ran at every start until 2026-10-08 is removed, with
its two probes: it opened a test port through UPnP (60000–63999), asked
whether NAT-PMP answered, and when either did wrote
`SECURITY-WARNING-insecure-nat` to every contact but the owner's own
devices (and `SECURITY-RESOLVED-nat-fixed` once both closed).  A note
where it stood in `rmail.lua` tells this.  Marks it left in `.state/`
(`nat_security_vulnerability_active`, `nat_security_warned.json`) are no
longer read or written; contacts it warned are told nothing more.  #414
(naming the sender in that warning) has nothing left to change.

**At install** — `scripts/install.sh`, its last step before cleaning up,
is the one place the router is checked: `upnpc -s` (does a UPnP router
answer discovery?) and `natpmpc` (does a NAT-PMP router answer?), opening
nothing, with a boxed warning to the person installing for each that
does and advice to switch it off in the router.  It tells no contact.  It
needs the programs, which the installer offers to build into
`deps/bin/` (or finds on the program path).

**Tested** by `scripts/test-router-left-alone.sh`: a throwaway checkout
whose `deps/bin/` holds stand-in `upnpc`/`natpmpc` that record each run.
Defaults → neither is run, the log has no router lines, no security
message is written.  `auto_port_forward = true` → `upnpc` is run once, to
open the port, and the opening is recorded.  Started again with the
defaults → `upnpc -d` removes it, and nothing else runs.  On the code
before this change, a default start ran `upnpc -s` and `natpmpc`.

`scripts/validate-router-settings.sh` checks from outside that the port
answers (#106's plain answer) and reports the router's settings.

## Intended Behavior

**The daemon never touches the router unless its config asks it to open
the port.  Finding out whether the router has UPnP or NAT-PMP switched on
is the installer's job, done once, reported to the person installing.**

- **No security check in the daemon.**  It runs neither router program at
  start-up, sends no warning or resolved message, and writes no warning
  state.  The check's code is removed rather than switched off: nothing
  would call it, and the installer's own probe covers the need.
- **Marks left by earlier runs** (`.state/nat_security_vulnerability_active`,
  `.state/nat_security_warned.json`) are left as they are; a contact
  already warned is told nothing more.
- **Asking the router stays off by default** (`auto_port_forward`,
  already `false`): rmail does not enable UPnP functionality on its own.
  The removal of an earlier run's mapping (`cleanup_old_mapping`) acts
  only on a mapping this mailbox recorded in `.state/nat_mapping.json`;
  with none recorded it runs nothing.
- **The installer's probe stays** as the place the owner learns the
  router's state, with its advice: switch UPnP and NAT-PMP off in the
  router and forward the port by hand.
- **The documents say the same**: the README's "Automatic port
  forwarding" section and `docs/.templates/nat-traversal-report.md`
  describe the probe as the installer's, and no longer describe a
  start-up check or messages to contacts.
- **Tests never touch the router**: a start-up with the defaults runs
  neither program, proven with stand-ins in the daemon's own
  `deps/bin/` (which the daemon looks in first) that record being run;
  with `auto_port_forward = true` the stand-in is run to open the port,
  so the opt-in still works.

## Suggested Implementation Steps

1. `rmail.lua`, `main`'s router work after binding: drop the call to the
   security check; delete `nat.security_check`.  Leave
   `nat.cleanup_old_mapping` (it acts only on a recorded mapping) and the
   `auto_port_forward` block as they are.
2. `scripts/install.sh`: the step list at its top says the probe is the
   only place the router's state is checked, and why.
3. README ("Automatic port forwarding") and
   `docs/.templates/nat-traversal-report.md` (the security check section
   and "exists for awareness"): the probe is the installer's; the daemon
   never probes; warned contacts are told nothing more.
4. Test `scripts/test-router-left-alone.sh`: a throwaway checkout whose
   `deps/bin/` holds stand-in `upnpc` and `natpmpc` that append each call
   to a file.  Default config → the file stays empty and the log has no
   router lines.  `auto_port_forward = true` → the stand-in `upnpc` is
   run to add the port, and the log says the port was mapped.
5. The phase 4 progress file (regenerate:
   `scripts/generate-phase-progress.lua`).

## Related documents

- `docs/.templates/nat-traversal-report.md`, `docs/.templates/ports-explained.md`
- `scripts/install.sh` (the router probe), `scripts/validate-router-settings.sh`
- `#412`, `#413`, `#414`, `#106`
