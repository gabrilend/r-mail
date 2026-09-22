# #387 — A blocking sync cycle stalls inbound requests (head-of-line blocking)

## Problem

The main loop multiplexes with `socket.select()`, but `run_sync_cycle` is
synchronous: it builds a batch of outbound ops and waits for them, real
network timeouts included. While the daemon is inside that call it is
**not** in `select()`, so it cannot accept or read from client sockets.

Any client talking to the daemon — the Android app most of all — is
therefore served only in the gaps *between* sync cycles. One slow or dead
contact adds its full connect timeout to every cycle, and every inbound
request waits that long.

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

## Possible directions

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

## Status

Open. Diagnosed 2026-09-22. Severity much reduced by #377, mechanism
unchanged.
