# #324 — Batch sync operations per contact with connection pre-check

## Problem

The sync cycle tries each operation independently. If a contact is
unreachable, every operation for that contact fails one by one, wasting
time and producing noisy logs (e.g. 10 separate "failed to notify"
messages for one offline contact).

## Desired behavior

1. **Connection pre-check**: Before running operations, attempt to connect
   to each contact. If the connection fails, skip all operations for that
   contact. Collect all unreachable contacts into a single log line per
   cycle, e.g. `unreachable contacts: alice, bob, marty, kyle`.

2. **Batch operations**: If connection succeeds, queue all pending
   operations for that contact and run them sequentially over the same
   connection.
3. **Parallel contacts**: Operations for different contacts can run in
   parallel (coroutines), since they're idempotent and atomic.

## Traffic analysis resistance (future consideration)

- Failed connection attempts should send a decoy packet of roughly the same
  size as a real operation, to act as a heartbeat that masks whether the
  contact is reachable.
- Successful packets should be padded to approximately match decoy size,
  with ~20% variability.

Implement both of these as opt-in hook scripts / helpers rather than
config switches. A config switch applies to the whole mailbox, but a
hook can be scoped per-contact, per-time-of-day, or on any other
criterion the user cares about. Mailbox-wide config options should be
reserved for things that genuinely must apply uniformly.

## Source

From `unsorted-issue-3`.
