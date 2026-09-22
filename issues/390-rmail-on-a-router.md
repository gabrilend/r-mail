# #390 — Run rmail on a router

## Why

The router is the one machine in the house that is always on, never moves,
and **holds the public IP directly**. Running the daemon there removes
several whole classes of problem rather than mitigating them:

| problem | why it disappears |
|---|---|
| suspend (#389) | a router does not sleep |
| port forwarding | the daemon is already on the WAN interface |
| hairpin NAT | LAN clients reach it directly; no loopback path |
| LAN IP changes (#302) | no internal address to forward to |
| dynamic public IP (#379) | still moves, but the daemon sees it on its own interface instead of asking a DNS service |

That last one is worth dwelling on: on a router, detecting our own public
address stops being an external query with a confirmation step and becomes
reading the WAN interface. Most of #379's machinery becomes unnecessary
there.

## Feasibility

Good. OpenWrt packages everything the daemon needs:

- `lua5.1` — and `run-rmail.sh` already falls back through `lua5.1`
- `luasocket`
- `libopenssl` — `rmail_crypto.c` uses the EVP API (`EVP_sha256`,
  AES-256-GCM) plus the Lua C API, both present

## Work required

1. **Cross-compile the C modules** — `rmail_crypto.so` and
   `rmail_inotify.so` for MIPS and ARM. This is the same road as #383
   (portable drives on more than one kind of processor), so the two should
   share a toolchain story rather than each inventing one.
2. **Storage.** Do **not** put a mailbox on the router's internal flash.
   Mail is write-heavy, flash has limited erase cycles, and a bricked
   router is worse than a lost mailbox. Require USB storage and refuse to
   install to flash.
3. **`inotify` availability.** Present on OpenWrt, but confirm the watcher
   works on the overlay/USB filesystem actually in use, since the outbox
   watcher is what makes local writes sync immediately.
4. **Packaging** — an OpenWrt package, or an install path that works with
   the router's own package manager.

## Constraints, and why they are acceptable

- **RAM**: the daemon sits at ~13MB RSS. Routers with 128MB+ are fine;
  anything with 32MB is not.
- **CPU**: AES-256-GCM without hardware acceleration, but at this message
  volume it is irrelevant. Attachment chunking is the only place it could
  be felt.
- **No `luajit` on MIPS** in practice — `lua5.1` is the target, so avoid
  anything JIT-specific. Worth noting the daemon is already near Lua's
  200-local limit in the main chunk (see the `ctimer`/`addrchk`/`paths`
  tables); plain Lua 5.1 has the same ceiling.

## Open questions

- Does the 200-local ceiling behave identically on stock Lua 5.1 as on
  LuaJIT? Needs checking before assuming the file loads at all.
- Is a router with a mailbox on it still "the mailbox is the installation"
  (#382), or does the USB stick become the mailbox and the router merely
  the host?
- Security posture: a daemon on the WAN interface is directly exposed,
  with no NAT in front of it. The wire protocol is authenticated and
  encrypted, but unauthenticated connection handling becomes the attack
  surface rather than a router's firewall.

## Status

Open. Feasibility assessed 2026-09-22; no implementation.
