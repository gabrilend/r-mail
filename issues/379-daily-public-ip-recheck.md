# #379 — Re-check public IP once per day at a random time

## Problem

Public IP detection runs **exactly once, at startup**.
`detect_ip_change` (`rmail.lua:4150`) is called from a single site —
`rmail.lua:5195`, inside `init_runtime`:

```lua
pcall(detect_ip_change, rt.my_name, rt.port)
pcall(detect_ipv6_change, rt.my_name, rt.port)
pcall(check_lan_ip_change, rt.port)
```

There is no re-check anywhere in the main loop.  A mid-run address
change is therefore invisible to the daemon *by construction* — and
this daemon's normal state is to run for months at a time.

### This has already cost real data

Captured 2026-09-21.  The daemon had been up since **Aug 6**.  At that
boot it queried, got `184.3.192.218`, matched the stored value, and
never looked again.  The ISP moved the address to `97.120.253.166`
sometime after — the phone's uploads stop dead on **Aug 25**, which
dates it.

Consequences, all downstream of the one missed check:

- `.state/public_ip` still read `184.3.192.218`, 46 days stale.
- No address-change notification was ever queued, so every contact
  still had the dead address.
- The Android client kept dialing `184.3.192.218` for both mailboxes
  and its uploads failed silently.  **41 outbox notes**, written between
  Aug 25 and Sep 21, never left the phone.
- `kuvalu` at `184.3.192.218:8025` became unreachable for the same
  reason.

The detection code itself is fine.  Queried by hand from the same
machine on 2026-09-21, all three providers answered correctly and
agreed:

```
opendns   : 97.120.253.166
cloudflare: 97.120.253.166
google    : 97.120.253.166
```

It works.  It just never runs.

## Requirements

From the 2026-09-21 discussion:

1. **Once per day.**
2. **At a 100% random time** — not a fixed hour, not top-of-hour, not
   an interval offset from boot.
3. **One provider is enough** for the routine probe.

## Proposed design

### Scheduling

Keep a `next_ip_check` timestamp in the runtime table.  After each
check, draw a fresh uniform offset in `[0, 86400)` and set
`next_ip_check = now + offset`.  The main-loop sleep calculation
(`rmail.lua:5346`) takes it into account alongside the sync interval —
and alongside the per-contact timers from #377, which lands in the same
part of the loop and should be written with that in mind.

Re-drawing the offset after *every* check (rather than fixing a
per-install hour) is what satisfies "100% random": the probe walks
freely around the clock instead of settling into a pattern.  That also
happens to be the right answer for traffic analysis — a daily beacon at
03:14 every day is a fingerprint; a uniformly scattered one is much
weaker signal.

### Gotcha: `math.random` is effectively unseeded

**`math.randomseed` is never called in practice.**  The only call site
is `rmail.lua:522`, inside the `/dev/urandom` *fallback* branch of
`uuid()`:

```lua
local function uuid()
    local f = io.open("/dev/urandom", "rb")
    if not f then
        math.randomseed(socket.gettime() * 1000)
        ...
```

On any normal Linux host `/dev/urandom` opens, the fallback never runs,
and the seed is never set.  Under LuaJIT that means `math.random`
replays the same sequence on every process start.

So a daily offset drawn from `math.random` would produce the **same
"random" time on every boot** — precisely the failure the requirement
is trying to avoid.  Draw the offset from `/dev/urandom` instead, the
same source `uuid()` already prefers.

Worth noting the same bug already undermines `shuffled_ip_services()`
(`rmail.lua:4113-4121`), whose comment claims traffic "spreads across
the list" so no resolver gets pinned as primary.  With a fixed seed the
shuffle is identical every run, so it doesn't.  Fixing the seeding once,
centrally, repairs both — and is probably the smaller change.

### One provider, but keep confirmation for changes

The routine probe uses a single service, per the requirement.  But
`detect_ip_change` currently runs `verify_ip_change` before notifying
(`rmail.lua:4181-4186`), which deliberately re-queries a **different
provider** — not just a different resolver IP — on the grounds that two
Cloudflare anycast endpoints would agree whether the answer is right or
wrong.

That guard is worth keeping, because the cost is asymmetric.  A missed
change costs one day of staleness.  A *false* change broadcasts a bad
address to every contact and rewrites their contacts files, which is
much harder to walk back.

Recommended shape: **probe with one provider; if — and only if — it
differs from the stored value, confirm with a second before notifying.**
Since the address is unchanged on almost every day, this is one DNS
query per day in the common case and two on the rare day it matters.
That satisfies "we only need to check one of the providers" for the
routine cost without giving up the safety property.  Flagged as an open
question in case the intent was to drop confirmation entirely.

### Reuse, don't duplicate

`detect_ip_change` already does the compare / verify / write / queue-
notifications sequence.  The daily check should call it, not
reimplement it.  The only change inside it would be the single-provider
probe path.

## Open questions

- Confirmation-on-change: keep it (recommended above) or drop it?
- Should `detect_ipv6_change` and `check_lan_ip_change` — the other two
  startup-only calls sitting right beside it at `rmail.lua:5195-5197` —
  also move onto the daily timer?  The LAN one especially: the
  `lan-ip-changed` notice in this mailbox shows it already fired once
  for real (`192.168.0.6` → `192.168.0.22`).
- If the daily probe **fails** (no network, resolver down), does it
  retry sooner than 24h, or wait the full day?  A failed probe must not
  be mistaken for "no change" — the existing early-return on
  `not new_ip` handles that correctly today and should be preserved.
- `handle_api_myaddress` (`rmail.lua:4360`) already calls
  `check_public_ip()` live on **every** phone `/api/myaddress` request,
  and discards the result for state purposes.  Should that path feed the
  change detector too?  It's a free signal that fires whenever the phone
  talks to us — though note it can't help in the exact scenario that
  motivated this issue, since the phone couldn't reach the daemon at all.
- Persist `next_ip_check` across restarts, or re-draw on boot?  Re-draw
  is simpler; persisting avoids a restart-loop re-probing repeatedly.
- Does the daily check belong to the same timer machinery as #377's
  per-contact timers, or stay a separate scalar?  They land in the same
  main-loop sleep computation and shouldn't be designed independently.

## Origin

Filed 2026-09-21, after tracing 41 stranded Android outbox notes to a
public IP change the daemon never noticed because it had not restarted
since Aug 6.  Root cause of the data loss investigated alongside #377
and #378.

## Status

**Implemented 2026-09-22**, with one change from the title: the period is
**36h ±12h** (uniform over `[24h, 48h)`), not once per day.  A window wider
than a day cannot land in the same part of the clock twice running, and a
36h mean is not a divisor of 24h, so the check precesses through the day
instead of settling into a slot.

Decisions taken (resolving the open questions above):

- **Confirmation on change: kept.**  The costs are asymmetric — a missed
  change costs one window of staleness, a false one broadcasts a bad address
  to every contact and rewrites their contacts files.
- **All three checks moved onto the timer**, not just public IPv4.  They were
  the same bug on three consecutive lines, and the LAN check has already
  fired for real here (`192.168.0.6` → `.22`); a stale LAN IP silently breaks
  the router's port-forward target.
- **A failed probe retries in 1h**, not a full window.  `detect_ip_change`
  now returns whether any provider answered, so "no answer" and "no change"
  are finally distinguishable.
- **`next_addr_check` is re-drawn on boot**, not persisted — simpler, and a
  restart loop cannot pin the probe to one time of day.
- The generator is **reseeded on every check**, so a months-long process does
  not ride a single boot-time seed for its whole life.

The "one provider is enough" requirement needed no code change:
`check_public_ip` already returns on the first provider that answers, and
`verify_ip_change` only runs when the address actually differs.

The `math.randomseed` gotcha described above was real and is fixed centrally,
which also repairs `shuffled_ip_services()`.
