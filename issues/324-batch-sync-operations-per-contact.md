# #324 — Batch sync operations per contact with connection pre-check

## Problem

The sync cycle tries each operation independently. If a contact is
unreachable, every operation for that contact fails one by one, wasting
time and producing noisy logs (e.g. 10 separate "failed to notify"
messages for one offline contact).

## Desired behavior

1. **Connection pre-check**: Before running operations, attempt to connect
   to each contact. If the connection fails, skip all operations for that
   contact (single log line instead of N).
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

## Source

From `unsorted-issue-3`.
