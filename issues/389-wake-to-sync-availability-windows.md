# #389 — Wake-to-sync: scheduled availability windows for a machine that sleeps

## Problem

rmail assumes the daemon is listening. A laptop that suspends is
unreachable while it sleeps, so contacts' deliveries fail and — since
#377 — they back off, up to the 2h ceiling. A sleeping mailbox looks
indistinguishable from a dead one.

This is not hypothetical. This machine has `HandleLidSwitch=suspend`, and
its suspend at `Aug 25 00:19:09` is the same day the phone's uploads
stopped. Resume is when a residential lease gets renewed, so suspend is
also what *moved* the public IP that #379 then failed to re-detect.

## Why polling on wake is not enough on its own

Waking to run a sync cycle only helps **outbound**. rmail is push:
contacts deliver *to* us. Waking, finding nothing because nobody could
reach us, and sleeping again accomplishes nothing.

## Design: announce, then hold a window open

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
2. **Announce to every contact** (#388).
3. **Hold the window open** for N seconds while they deliver.
4. **Sleep.**

What a wake *skips* is the one-time setup, not the IP check: port binding,
UPnP/NAT-PMP probing (~8s against a router that ignores you), inotify
watcher creation, multicast join. Those survive suspend.

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
hosts, or a laptop that must sleep. #390 (rmail on a router) removes the
need entirely for anyone whose router can run it.

## Status

Open, low priority. Design recorded; not scheduled.

The "announce, hold a window open, stop" step now exists as
`rmail.lua <config> --once[=SECONDS]` (added for portable drives in
#388).  A wake-to-sync implementation can call it from a timer.
