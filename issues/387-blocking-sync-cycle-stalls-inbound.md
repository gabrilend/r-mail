# #387 — A blocking sync cycle stalls inbound requests (head-of-line blocking)

## Current Behavior

The main loop multiplexes with `socket.select()`, but `run_sync_cycle` is
synchronous: it builds a batch of outbound ops and waits for them, real
network timeouts included. While the daemon is inside that call it is
**not** in `select()`, so it cannot accept or read from client sockets.

Any client talking to the daemon — the Android app most of all — is
therefore served only in the gaps *between* sync cycles. One slow or dead
contact adds its full connect timeout to every cycle, and every inbound
request waits that long.

**Since 2026-10-04, in part.**  While a batch waits on its requests, the
listening sockets are watched too (`ctimer.answer_while_sending`).  A
caller the batch is itself dialing is answered at once, sealed, with
`503 {"busy": true}`; the caller's daemon reads that as "reached — retry
at the floor", not as a refusal and not as unreachable, and tries none of
its other addresses.  Every other caller is held, its first frame read,
and handed to the main loop the moment the cycle ends — served as soon as
it would have been, but no longer left to time out unread.  That ends the
mutual stall below (two daemons that each had something for the other).
Requests are still not *processed* during a cycle — handlers write
records the cycle holds in memory — which is the rest of this issue.
Test: `scripts/test-busy-while-sending.sh`; the two-daemon
`scripts/test-attachment-round-trip.sh` locked up without it.

## Observed

Captured 2026-09-22, before #377 landed. `aurelia` had been unreachable
since May at a superseded address:

```
12:45:28  timeout connecting to 97.120.230.43:50000
12:45:28  phone created outbox: pic-in-dinosaur-hoodie
12:45:28  phone created outbox: 20260825-160947.txt
12:45:36  timeout connecting to 97.120.230.43:50000
12:45:36  sent: pic-in-dinosaur-hoodie -> kuvalu
```

Two ~8s stalls per cycle, so roughly **94% of every cycle was spent
waiting on a host that had been gone for four months**, and the phone's
uploads appeared pinned to cycle boundaries. The phone was ready
throughout; it simply could not be served.

Downstream, this was the trigger for #386: requests queuing behind the
stalls reached the client's 30s read timeout.

## What #377 did and did not fix

Per-contact backoff removes the *common* case: a dead contact is dialed
~12 times a day instead of ~5,700, so most cycles no longer stall. Aurelia
timeouts dropped from 67 in nine minutes to 1 after the restart.

It does not fix the mechanism. A contact that is merely *slow* rather than
dead still blocks every cycle it participates in, and a contact freshly
gone unreachable stalls cycles until backoff climbs.

## Intended Behavior

- **Non-blocking outbound.** The batch already fans out concurrently
  (six queued ops produced six connects in the same second), so the gap is
  the cycle *waiting* on the batch rather than the batch itself being
  serial. Driving those sockets through the same `select()` as inbound
  would remove the stall without threads.
- **Shorter connect timeout** for contacts with a recent failure. Cheap,
  partial, does not help a contact that accepts and then stalls.
- **Threads.** Considered and set aside 2026-09-22: the batch is already
  concurrent, so threading would add locking around the state files and
  the contacts file to solve a problem backoff has mostly addressed.

## Suggested Implementation Steps

1. Drive the batch's sockets from the main loop's `select` (the first
   direction): a sync cycle becomes a coroutine resumed when its sockets
   are ready, and requests are served meanwhile.  The state files are then
   read and written by both at once — every handler that writes a record
   the cycle holds in memory (the answers of #406 do) must be made safe
   first, or the cycle re-reads after each wait.
2. Test: two real daemons that each have something to send the other at
   the same moment both deliver within one cycle — the case that today
   makes every two-mailbox test fragile (2026-10-04, below).

## Status

Open. Diagnosed 2026-09-22. Severity much reduced by #377, mechanism
unchanged.

2026-09-23: #397 turns one sync into several passes, repeated until a
check plans nothing.  A longer sync is a longer stall for inbound
requests, so this gets worse when #397 lands unless outbound becomes
non-blocking first or alongside.

2026-10-04: seen again, sharply, while testing #406–#409 with two and
three real daemons on one machine.  After a sender's start-up
announcement a receiver dials the announced public address to confirm it
(#388); that address does not loop back on this machine, so the dial
waits its full 8 seconds, during which the receiver answers nothing — and
the sender, sending pieces to it at that moment, times out and backs off
for six minutes.  Every time two daemons both had something to say they
stalled each other.  The tests now use a stand-in recipient that answers
at once and never dials (`scripts/lib/fake-recipient.lua`); fixing this
would let them use real daemons again.  (The two-mailbox tests that did
pass before 2026-10-04 were helped by a crash: the address handler threw
right after saving a key-only contact's address, so the confirming dial
never happened.)
