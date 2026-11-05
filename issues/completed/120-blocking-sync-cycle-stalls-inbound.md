# #120 — A blocking sync cycle stalls inbound requests (head-of-line blocking)

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

Captured 2026-09-22, before #115 landed. `aurelia` had been unreachable
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

Downstream, this was the trigger for #804: requests queuing behind the
stalls reached the client's 30s read timeout.

## What #115 did and did not fix

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
   the cycle holds in memory (the answers of #312 do) must be made safe
   first, or the cycle re-reads after each wait.
2. Test: two real daemons that each have something to send the other at
   the same moment both deliver within one cycle — the case that today
   makes every two-mailbox test fragile (2026-10-04, below).

## Status

**Built 2026-11-05** (the first direction, step 1, and the test of step 2;
see "Built" below).  Diagnosed 2026-09-22. Severity much reduced by #115, mechanism
unchanged.

2026-09-23: #121 turns one sync into several passes, repeated until a
check plans nothing.  A longer sync is a longer stall for inbound
requests, so this gets worse when #121 lands unless outbound becomes
non-blocking first or alongside.

2026-10-04: seen again, sharply, while testing #312–#208 with two and
three real daemons on one machine.  After a sender's start-up
announcement a receiver dials the announced public address to confirm it
(#409); that address does not loop back on this machine, so the dial
waits its full 8 seconds, during which the receiver answers nothing — and
the sender, sending pieces to it at that moment, times out and backs off
for six minutes.  Every time two daemons both had something to say they
stalled each other.  The tests now use a stand-in recipient that answers
at once and never dials (`scripts/lib/fake-recipient.lua`); fixing this
would let them use real daemons again.  (The two-mailbox tests that did
pass before 2026-10-04 were helped by a crash: the address handler threw
right after saving a key-only contact's address, so the confirming dial
never happened.)

2026-11-05: built.  The two-mailbox tests can use real daemons again;
the ones that use the stand-in were left as they are.

## Built (2026-11-05)

**The cycle is a coroutine of the main loop.**  `main` starts
`run_sync_cycle` in a coroutine (`ctimer.cycle`) and resumes it.  Where
the batch used to wait in its own `select`, it now yields its sockets and
a deadline (`ctimer.wait_for_sockets`); the main loop adds them to its
own `select`, serves every request that arrives meanwhile, and resumes
the cycle when one of its sockets is ready or the deadline passes.  What
used to follow the cycle inline (the held callers, `last_sync`, the NAT
renewal, the inotify drain, the contacts tidy) runs when it ends
(`finish_cycle`).  Contacts and outbox changes, the address check and
the start of a new cycle wait until no cycle runs; one cycle at a time.
A batch run outside the cycle keeps the old wait and the `busy` answer.

**State files: leases, and versions as the backstop.**  Each cycle step
that keeps a state file in memory across a wait names it
(`ctimer.hold` in `run_sync_cycle`):

| step | holds |
|------|-------|
| outbox | `outbox.json`, `chunks-outgoing.json` |
| inbox | `inbox.json` |
| address notices | `pending-address.json` |
| consent answers | `consent-responses.json` |
| attachment pieces | `chunks-outgoing.json`, `outbox.json` |
| cancellations | `consent-pending.json` |

The consent check sends nothing and holds nothing.  The outbox folder's
files go with `outbox.json`: a step holding it may strike a recipient
from a file or remove it as finished after its wait, judged on the file
as it was before, so the phone's writes and deletions of outbox files
wait for that lease too.  A request that loads or saves a held file waits (its coroutine yields `lease`) until the step
lets go; a request touching anything else is answered at once.  Every
save counts a version, and a coroutine that saves a file someone else
saved after it read it gets an error naming the file and writes nothing,
so a lease left off is a loud failure, never a lost update.

**Timers.**  A contact heard from during a cycle is settled when it ends:
one the cycle reached keeps the due time its success set (else two
daemons that just exchanged mail dial each other again at once); anyone
else is due now, as `saw_inbound` makes them between cycles.  A request
that makes a contact due now (the phone's consent answer) is likewise
settled after the cycle, so the cycle's bookkeeping cannot push it back
to the floor (`ctimer.due_now`).

**Tests.**
- `scripts/test-serve-while-syncing.sh` (new, step 2): two real
  daemons, each with a message for the other and one for a stand-in that
  holds its answer 6 seconds, started three times.  Each time both
  messages arrive before either stand-in has answered, so inside each
  daemon's first cycle (0.1 to 0.2 s after start); no busy answers,
  timeouts, backing off or refused saves.  Run against `main` (5645279)
  the same script fails every round: each daemon answers the other
  `busy`, and the messages arrive 7 to 11 s after start, once more than
  30 s.
- `scripts/test-busy-while-sending.sh` (rewritten): while the daemon
  waits on alice, alice and bob, direct and from a web page, are answered
  properly at once; bob's answer to an attachment offer, which reads
  `chunks-outgoing.json`, waits for the outbox step and no longer.  With
  the outbox step's leases removed by hand, that case fails, as it
  should.

## Decisions (2026-11-05, the owner can overturn any of these)

1. **Leases plus versions, not re-reading after each wait.**  Step 1
   offered either.  Re-reading would mean auditing every builder for
   every value it keeps across a wait; a lease is one line per step and
   the version check catches any lease that is missing.
2. **The `busy` answer stays, outside the cycle only.**  Inside the
   cycle nobody is answered busy any more.  Batches run outside it (none
   in the normal loop today) keep the 2026-10-04 behaviour rather than
   lose it.  The daemon still understands a `busy` answer from an older
   daemon.
3. **Requests that touch a held file wait; they are not answered busy.**
   The wait is one step's network wait (8 s at worst per contact), the
   same as before for that one request, and everyone else is served.
4. **The inotify drain stays at the end of the cycle.**  An outbox file
   the phone writes during a cycle is honoured by syncing again at once
   (`ctimer.outbox_written`).  A file saved by an editor or hook during a
   cycle still waits for a timer, as before; that is #119, left to #121.
5. **No shorter connect timeout.**  With requests served during the
   wait, a slow contact costs only its own messages; the second
   direction is no longer needed.
6. **No threads**, as decided 2026-09-22.
7. **The address check still blocks, and is left alone.**  `addrchk.run`
   (asking public services for this machine's address, and the home
   network's) runs in the main loop outside any cycle, at start-up and
   then hours apart, and the loop serves nobody while it asks.  It is
   not a sync cycle and not this issue; making it a coroutine the same
   way would be a small follow-up if it is ever seen to stall.
8. **The stand-in tests stay.**  Moving `test-attachment-answers.sh` and
   `test-shared-packed-copy.sh` back to two real daemons is possible now,
   but is a change of their own.

