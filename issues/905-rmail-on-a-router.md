# #905 — Run rmail on a router

## Current Behavior

rmail does not run on a router.  Feasibility was assessed on 2026-09-22
(below); nothing is built.


## Intended Behavior

The router is the one machine in the house that is always on, never moves,
and **holds the public IP directly**. Running the daemon there removes
several whole classes of problem rather than mitigating them:

| problem | why it disappears |
|---|---|
| suspend (#419) | a router does not sleep |
| port forwarding | the daemon is already on the WAN interface |
| hairpin NAT | LAN clients reach it directly; no loopback path |
| LAN IP changes (#412) | no internal address to forward to |
| dynamic public IP (#410) | still moves, but the daemon sees it on its own interface instead of asking a DNS service |

That last one is worth dwelling on: on a router, detecting our own public
address stops being an external query with a confirmation step and becomes
reading the WAN interface. Most of #410's machinery becomes unnecessary
there.

## Feasibility

Good. OpenWrt packages everything the daemon needs:

- `lua5.1` — and `run-rmail.sh` already falls back through `lua5.1`
- `luasocket`
- `libopenssl` — `rmail_crypto.c` uses the EVP API (`EVP_sha256`,
  AES-256-GCM) plus the Lua C API, both present

## Suggested Implementation Steps

1. **Cross-compile the C modules** — `rmail_crypto.so` and
   `rmail_inotify.so` for MIPS and ARM. This is the same road as #619
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
  (#102), or does the USB stick become the mailbox and the router merely
  the host?
- Security posture: a daemon on the WAN interface is directly exposed,
  with no NAT in front of it. The wire protocol is authenticated and
  encrypted, but unauthenticated connection handling becomes the attack
  surface rather than a router's firewall.

## Findings (2026-11-06)

Checked on an x86-64 Linux machine, not on a router: what can be checked
without one.  No router was run, and nothing below is a router result.

1. **Lua 5.1 cannot run rmail.** `rmail.lua` uses `goto` (eight places on
   main, for example `goto continue_batch` in the batch sender), and Lua
   5.1 has no `goto`: stock Lua 5.1.5 refuses the file at once,
   `rmail.lua:3230: '=' expected near 'continue_batch'`.  So the 200-local
   question above is not the first obstacle on 5.1; the file never gets
   that far.  The libraries in `libs/` compile on 5.1; only `rmail.lua` does
   not.  LuaJIT has `goto` and reads the file (checked).  The
   "Feasibility" and "Constraints" sections above, which name `lua5.1` as
   the target, are wrong on this point.
2. **OpenWrt's Lua for rmail is 5.3.**  From OpenWrt's package
   definitions, read 2026-11-06:
   - `lua5.3`: 5.3.5, in the core tree's `package/utils/lua5.3`, read in
     a staging copy.
   - `luasocket5.3`: luasocket 3.1.0 built for Lua 5.3, in the packages
     feed's `openwrt-24.10` branch.  That Makefile defines two variants,
     `luasocket` (for Lua 5.1) and `luasocket5.3`.
   - `lua5.4`: 5.4.7, in the packages feed for 24.10, but no luasocket
     variant is built for it.
   - OpenWrt's plain `lua` is 5.1, kept for its web interface.

   So a router would run rmail on `lua5.3` with `luasocket5.3` and
   `libopenssl`; `rmail_crypto.c` and `rmail_inotify.c` would be compiled
   against Lua 5.3's headers.
3. **rmail runs on stock Lua 5.3.**  On Ubuntu's Lua 5.3.6, with Ubuntu's
   luasocket for 5.3 and the two C modules compiled here against the 5.3
   headers (`cc -shared -fPIC -I/usr/include/lua5.3`), main's whole test
   suite was run with Lua 5.3 as the daemon's interpreter: LUA53_RESULT.
   The five that fail are the five that fail on Lua 5.4 in this container
   as well (they need a browser, a real home network or a service
   manager).  The 200-local limit is the same in 5.3 as in 5.4 (both
   compile the main chunk).
4. **Memory.**  One daemon with one contact it cannot reach, 20 seconds
   after starting, on x86-64: 8.1 MB resident on Lua 5.3, 8.0 MB on Lua
   5.4 (`VmRSS`, equal to `VmHWM`).  A MIPS or ARM router will differ, and
   attachments add their buffers; the figure only says the order of size
   (the "~13MB" above) holds.
5. **`run-rmail.sh` now passes over a Lua that cannot read a `goto`.**
   With no compiled Lua it used to start the first interpreter on the
   PATH, so on a router with only OpenWrt's `lua` (5.1) the daemon died on
   the syntax error above, which names a line of rmail.lua and not the
   cause.  It now tries each one with a one-line `goto`, starts the first
   that reads it, and otherwise says that rmail needs Lua 5.2 or later or
   LuaJIT, naming the packages to add on OpenWrt.
   `scripts/test-run-rmail-interpreters.sh` checks it (7 cases; 6 of 6
   mutants caught).

## Decisions (2026-11-06)

- **The router target is Lua 5.3, not 5.1.**  Rewriting the eight
  `goto`s would make 5.1 possible, but OpenWrt carries 5.3 and a
  luasocket for it, so nothing is gained by holding the daemon to 5.1.
- **A mailbox on a router is still the installation (#102), on the USB
  drive.**  The drive holds the mailbox; the router is its host.  That is
  the shape #616/#619 already give a drive, and it keeps the mailbox off
  the router's flash (step 2).

## What is left for the owner, or for a router

- Every step above needs a router or an OpenWrt build tree: compiling the
  C modules with OpenWrt's toolchain (musl, not glibc; the generator of
  #617/#619 builds against glibc and would need an OpenWrt target),
  inotify on the router's USB filesystem, packaging, and refusing a
  mailbox on internal flash.
- Reading the public address from the WAN interface instead of asking a
  service (#410) is a daemon change that only makes sense on a router; it
  waits for a router to test on.
- The security question above (a daemon on the WAN interface with no NAT
  in front) is the owner's.

## Status

Open.  Feasibility assessed 2026-09-22; findings and the interpreter
check 2026-11-06; nothing built for a router itself.
