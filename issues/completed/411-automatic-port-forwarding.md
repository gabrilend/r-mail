# #411 — Asking the router to forward the port, and warning contacts when the router allows it

## Status

Completed — a blueprint written 2026-10-04 (#621) for what was built
before issue files described it.  #412, #413 and #414 refine it.

## Current Behavior

A mailbox behind a home router can only be reached if the router
forwards its port to this machine.  Two router protocols let a program
ask for that without the owner opening the router's settings: **UPnP**
and **NAT-PMP**.  The daemon uses them through the `upnpc` and `natpmpc`
programs, when present.

**Asking** — only with `auto_port_forward = true` in the config, after
the port is claimed (#101): UPnP first, then
NAT-PMP (an hour's lease); the mapping is recorded in
`.state/nat_mapping.json` and renewed every 30 minutes; at start-up a
mapping left by an earlier run is removed first.  Failure is a warning:
the port may still be forwarded by hand.

**The security check** — every start-up, whether or not forwarding is
asked for.  The same two protocols let *any* program on the network open
ports without asking anyone; malware uses them to get past the router.
The daemon probes: a UPnP router that grants a test mapping (removed at
once), a NAT-PMP router that answers.  If either is open:

- the log says so in three WARNING lines;
- every contact not yet warned (not the owner's own devices) is sent a
  message, written into the outbox as `SECURITY-WARNING-insecure-nat`:
  treat this connection as possibly compromised, send nothing sensitive,
  remind me to fix it;
- `.state/nat_security_vulnerability_active` is set.

When a later start-up finds both closed, the contacts who were warned
get `SECURITY-RESOLVED-nat-fixed`, and the marks are cleared.  The
owner's choice of closing them is #413; who the warning names is #414.

`scripts/validate-router-settings.sh` checks from outside that the port
answers (#106's plain answer) and reports the router's settings.

## Intended Behavior

As above.

## Suggested Implementation Steps

1. `rmail.lua`, the `nat` table: `get_local_ip`, `try_upnp_probe` /
   `_add` / `_delete`, `try_natpmp_probe` / `_add` / `_delete`,
   `create_mapping`, `cleanup_old_mapping`, `security_check`; the renewal
   in `main`.
2. `scripts/validate-router-settings.sh`; `scripts/install.sh` offers to
   install `upnpc` / builds `natpmpc` into `deps/`.

## Related documents

- `docs/.templates/nat-traversal-report.md`, `docs/.templates/ports-explained.md`
- `#412`, `#413`, `#414`, `#106`
