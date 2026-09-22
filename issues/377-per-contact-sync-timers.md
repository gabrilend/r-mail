# #377 — Per-contact sync timers, startup ping, reset on inbound contact

## Problem

The sync cadence is a **single global timer** shared by every contact,
with no per-contact failure backoff.  Two distinct bugs fall out of
that.

### 1. An unreachable contact becomes a permanent beacon

`sync_address_notifications` (`rmail.lua:4244`) re-queues its pending
`/update-address` op every cycle.  The entry clears only on success, or
if the contact is deleted from `contacts` — there is no backoff, no
attempt cap, no TTL.  Same story for the `deliver` / `update` /
`notify_deletion` op types: the recipient entry is written **only** on
success (`rmail.lua:3833-3839`), so a failure leaves the key absent and
the next cycle rebuilds the identical op.

Captured live on 2026-09-21.  `aurelia` has been unreachable since
roughly May; `.state/pending-address.json` still holds her entry, and
the daemon has been dialing `97.120.230.43:50000` ever since:

```
2026-08-06 02:24:13 timeout connecting to 97.120.230.43:50000
2026-08-06 02:24:21 timeout connecting to 97.120.230.43:50000
2026-08-06 02:24:21 unreachable contacts this cycle: aurelia
2026-08-06 02:24:21 idle, interval -> 30s
   ... identical every ~30s, for months
```

At the current testing values that is ~2 connects per 30s ≈ **5,700
connect attempts per day**, aimed at an address her own
`address-update` message superseded back in May.  It can never succeed,
so it will never stop.  This is not specific to a stale contact: *any*
contact who goes offline permanently becomes a forever-beacon.

### 2. Failure is self-sustaining, and it drags everyone else down

The interval only moves on the aggregate `did_work` flag
(`rmail.lua:5094-5100`):

```lua
if w1 or w2 or w3 or w4 or w5 or w6 or w7 then
    rt.interval = math.max(rt.min_interval, rt.interval - 240)
else
    rt.interval = math.min(rt.interval + 360, rt.max_interval)
end
```

A cycle in which the only "activity" was a failed op counts as idle, so
the interval parks at `max_interval` and stays there.  Worse, the
coupling runs both ways: one chatty contact holds the timer at minimum
and every other contact gets polled at that rate too, while one dead
contact's failures can't be backed off without also slowing the healthy
ones.  There is exactly one knob for N contacts with N different
reachability profiles.

Note that `note_contact_result` (`rmail.lua:560`) **already tracks
per-contact outcomes** for the #324 summary line — the per-contact
signal exists, it just isn't used for scheduling.

## Requirements

From the 2026-09-21 discussion, in the user's framing:

1. **Startup ping.**  On daemon start, send a ping to every contact.  It
   should be "basically the same as the other sync cycle pings" — not a
   new mechanism, just the normal cycle fired immediately at boot.
2. **Per-contact timers.**  Every contact gets its own independent
   timer.  No shared global interval.
3. **Reset on inbound.**  When a contact pings *us*, reset **that
   contact's** timer to the floor — not everyone's.
4. **Ceiling of 2h** for now (replacing the current 30s test value).

## Proposed design

### Timer state

Replace the single `rt.interval` with a per-contact table:

```lua
rt.contact_timers = {
    [name] = {
        interval  = 10,      -- current backoff, seconds
        next_due  = <epoch>, -- when this contact is next eligible
        last_ok   = <epoch>, -- last successful exchange
    },
}
```

Floor stays `min_interval` (10s); ceiling becomes 7200s (2h).  Growth on
a failed cycle should probably be multiplicative (×2) rather than the
current `+360` — additive from 10s to 7200s takes 20 cycles, doubling
takes ~10 and spends far less time in the noisy middle.  **Not decided
— see open questions.**

### Scheduling

`run_sync_cycle` currently builds ops for *all* contacts and hands them
to `http_post_batch_with_fallback` in one shot.  Per-contact timers mean
filtering the op list to contacts whose `next_due <= now` before the
batch send.  **This is the main refactor** and the part most likely to
have sharp edges — the op builders (`sync_outbox`, `sync_inbox`,
`sync_address_notifications`, chunk senders) each construct ops
independently, so the filter wants to live at one choke point rather
than being duplicated into each builder.

The main-loop sleep (`rmail.lua:5346`) currently computes time-to-next
from the single interval; it becomes `min(next_due)` across contacts.
Local triggers (outbox inotify, contacts inotify) keep their existing
short-circuit behaviour.

### Reset hooks

- **Success** — on any `results[i].ok` for a contact, reset `interval`
  to the floor and stamp `last_ok`.
- **Inbound** — the connection handler already resolves `contact_name`
  before dispatch (`rmail.lua:5064-5068`, where it is passed into
  `handle_deliver` / `handle_delete` / `handle_update_address`).  That
  is the natural hook: any authenticated inbound request from a contact
  resets their timer and marks them due immediately, so a reply goes out
  on the next loop iteration rather than up to 2h later.  This is what
  gives the system push-like latency between two online peers while
  keeping poll-based self-healing.
- **Startup** — seed every contact with `next_due = now` so the first
  cycle after boot contacts everyone.

### Persistence

Timers could live purely in memory (reset to floor on every restart) or
be persisted to `.state/`.  In-memory is simpler and self-correcting;
persisted avoids a restart loop re-storming a long-dead contact.
Leaning in-memory for v1 given restarts are rare.

## Open questions

- **What *is* a "ping"?**  There is no ping endpoint today.  Reuse
  `/peer-address` (exists, allowed for any contact, `rmail.lua:4351`)?
  Add a dedicated `/ping`?  Or is the "ping" simply "run this contact's
  normal queued ops, and if there are none, do nothing"?  The third
  reading means an idle contact pair exchange *nothing* at boot, which
  may or may not be the intent.
- Growth curve: ×2, or keep additive `+360`?  And does the floor stay
  10s, given that's a testing value (`rmail.lua:5135-5137`, marked
  `TODO: increase for production`)?
- Should a contact's timer be reset by *any* inbound request, or only
  by ones that indicate real liveness?  A failed decryption from a
  spoofed peer shouldn't reset anything.
- Startup ping with N contacts fires N connects at once.  Does that need
  jitter/stagger, or is N small enough not to care?
- How does this interact with #371 (log coalescing)?  Backoff massively
  reduces the repeat volume that motivated #371 — both are still worth
  having, but #371's urgency drops a lot once this lands.
- Does per-contact scheduling break the batching assumption in
  `http_post_batch_with_fallback`, which currently expects to fan out
  across contacts in one call?
- Should an op that has been failing for, say, 30 days be dropped
  entirely and surfaced to the user (a TTL, as distinct from a backoff)?
  The `aurelia` pending-address entry is the motivating case — no amount
  of backoff makes a permanently-wrong address correct.

## Origin

Filed 2026-09-21 after tracing why `aurelia` had been pinged
continuously for months at an address that had been superseded since
May, and confirming there is no backoff path anywhere in the daemon.

## Status

**Implemented 2026-09-22.**

Decisions taken (resolving the open questions above):

- **Ping** = an `/update-address` announce to every contact at boot — "hi,
  I'm still here, at this location".  Not a new endpoint: it queues the same
  pending-address entry an IP change queues, so it rides the ordinary sync
  cycle.  This also makes a restart a full repair for contacts holding a
  stale address for us, not just a re-detection.
- **Growth** stays additive `+360`, floor **30s**, ceiling **2h**, with
  **±30s jitter** on every due time so contacts that failed together do not
  stay in lockstep and re-storm together.
- **No TTL.**  A permanently-failing op is backed off, never dropped.  At the
  ceiling `aurelia` costs ~12 attempts/day instead of ~5,700, and nothing is
  discarded silently.
- **Reset on inbound** is hooked after successful decryption, so only a
  sender proving possession of the shared token can reset a timer.

The gate lives in `http_post_batch_with_fallback`, the single choke point
every outbound op passes through, rather than being duplicated into the six
op builders.  A withheld request is returned to its builder as an ordinary
failed result — which is the correct signal, since every builder already
treats failure as "leave the op queued and change nothing".

Not addressed here: #371 (log coalescing) is much less urgent now, as
predicted, since backoff removes most of the repeat volume.
