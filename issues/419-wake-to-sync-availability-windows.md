# #419 — Wake-to-sync: scheduled availability windows for a machine that sleeps

## Current Behavior

rmail assumes the daemon is listening. A laptop that suspends is
unreachable while it sleeps, so contacts' deliveries fail and — since
#115 — they back off, up to the 2h ceiling. A sleeping mailbox looks
indistinguishable from a dead one.

This is not hypothetical. This machine has `HandleLidSwitch=suspend`, and
its suspend at `Aug 25 00:19:09` is the same day the phone's uploads
stopped. Resume is when a residential lease gets renewed, so suspend is
also what *moved* the public IP that #410 then failed to re-detect.

## Why polling on wake is not enough on its own

Waking to run a sync cycle only helps **outbound**. rmail is push:
contacts deliver *to* us. Waking, finding nothing because nobody could
reach us, and sleeping again accomplishes nothing.

## Intended Behavior

The missing piece is that our announcement is an authenticated inbound
request *to them*, which hits `ctimer.saw_inbound` and resets **their**
timer for **us** to due-now. A contact backed off to two hours becomes due
immediately, and delivers on their next loop pass — sub-second, because
the announcement itself woke their `select()`.

So a wake is:

1. **Check our public IP.** Cheap (one UDP DNS query) and resume is
   precisely when the address moves, so this is the most valuable moment
   to check. Must come first: the announcement is only useful if it
   carries the current address.
2. **Announce to every contact** (#409).
3. **Hold the window open** for N seconds while they deliver.
4. **Sleep.**

What a wake *skips* is the one-time setup, not the IP check: port binding,
UPnP/NAT-PMP probing (~8s against a router that ignores you), inotify
watcher creation. Those survive suspend. (There was a multicast join too,
until LAN discovery was removed, #418.)

## Window length

Text mail needs seconds. Attachments are chunked and resume across cycles,
so a large one simply spans several windows and needs no special handling.
A window of ~60s is generous for the common case.

## Interval

Explicitly **not** tied to per-contact sync timers — with a 30s floor and
any live contact there would be no sleep at all, and the transitions cost
more than staying awake. A single global schedule (~15-30 min) decoupled
from `ctimer` gives a worst-case mail latency equal to the interval, which
is the honest trade: latency for power.

## Rejected: wake on incoming request

Appealing, but not available. A suspended host cannot receive a request —
that is what suspended means. It would need Wake-on-LAN, and:

- WoL over the internet needs the router to forward a magic packet to a
  sleeping host, which needs a static ARP entry. Fragile.
- WoWLAN (WoL over WiFi) is poorly supported and frequently broken.
- This machine is on WiFi (`wlo1`), so the wired path does not apply.

## Suggested Implementation Steps

1. A machine that wakes runs the daemon with `--once` (which already
   announces, syncs and stays reachable for a window, then exits), from a
   wake hook or a timer at the interval below.
2. Test: a mailbox run with `--once=30` delivers what was owed to it while
   it was away and exits after the window.

## Priority

**Low, and deliberately so.** For a machine that *is* a mailbox, disabling
suspend is simpler and strictly better:

```nix
services.logind.lidSwitchExternalPower = "ignore";   # plugged in = server
services.logind.lidSwitch = "suspend";               # on battery = laptop
```

Costs are modest: more heat with the lid closed, a battery aging at a
constant 100% on AC, ~10-25W. Thermal throttling protects the CPU.

This issue exists for people who cannot make that trade — battery-only
hosts, or a laptop that must sleep. #905 (rmail on a router) removes the
need entirely for anyone whose router can run it.

## Status

Built 2026-11-05, the first slice: a running daemon notices that its
machine slept, and on waking checks its address, owes every contact an
announcement, and makes every contact due at once.  This is steps 1 and 2
of a wake ("check our public IP", "announce to every contact") done by
the daemon that was already running, which is the common case on a
laptop that suspends with rmail under systemd.  The scheduled windows
for a machine that stays asleep (wake on a timer, hold a window, sleep
again) remain operating-system configuration around the existing
`--once[=SECONDS]`, as the suggested steps already say; nothing in rmail
was needed for that, and it is not tested here.

The "announce, hold a window open, stop" step exists as
`rmail.lua <config> --once[=SECONDS]` (added for portable drives in
#409).  A wake-to-sync timer can call it.

## Decisions (2026-11-05)

- **How a wake is noticed.**  The main loop's `select()` waits on the
  monotonic clock, which stops while the machine is suspended; the wall
  clock does not.  A wait that comes back more than `wake_gap` seconds
  later by the wall clock than it was asked to wait is taken as a sleep.
  No logind or D-Bus hook: rmail runs on machines without either, and
  this needs nothing outside the daemon.  A wall clock stepped forward by
  more than `wake_gap` reads the same way; the cost is one announcement
  nobody needed, so it is not guarded against.
- **`wake_gap` defaults to 60 seconds.**  The loop never asks to wait
  more than 3 seconds, so anything over a minute is not the daemon being
  slow; a shorter suspend is not worth announcing.  It is a config key so
  the test can use 3.
- **Address first, then the announcement** -- the order this issue gives,
  since the announcement is only worth sending with the current address.
  The check is the same one the daily re-check runs (#410), and it
  reschedules that check.
- **Every contact is made due at once**, not only those owed an
  announcement: contacts who tried us while we slept have backed off,
  and our own outgoing mail to them has waited too.  Contacts that only
  listen (#420) and contacts without an address are not announced to, as
  at start-up; the start-up announcement and this one are now one
  function, `addrchk.announce`.
- **Not done here:** scheduled wake windows (a systemd timer with
  `WakeSystem=true` that runs `--once`) are left to the machine's own
  configuration, and wake on an incoming request stays rejected for the
  reasons above.  The owner's words in this issue -- "low, and
  deliberately so", and that disabling suspend is better for a machine
  that is a mailbox -- are kept: this slice costs nothing on a machine
  that never sleeps.
- Test: `scripts/test-wake-to-sync.sh`, which plays the sleep by
  stopping the daemon (SIGSTOP) for 12 seconds.
