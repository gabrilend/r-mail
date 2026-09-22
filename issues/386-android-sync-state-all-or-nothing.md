# #386 — Android sync state is committed all-or-nothing, so proven uploads are re-sent

## Problem

`SyncManager.sync()` wraps its entire body in one `try`/`catch`, and
`store.writeSyncState(newState)` is the **last** statement before the
return. Every side effect in between — uploads, downloads, deletions,
contact pushes — is already durable on the server by the time it runs.

So a failure anywhere after the upload loop discards the record of work
that actually succeeded:

1. The upload loop uploads N files. All succeed. All are durable on the
   server, which logs `phone created outbox: <name>` for each.
2. Something later throws — `postContacts`, a download, a read timeout.
3. `writeSyncState` is never reached. `newState` is dropped on the floor.
4. Next sync recomputes `newOutbox = onDisk - inState`, which still lists
   all N files, and **re-uploads every one of them**.

## Observed

Captured live 2026-09-22 while the phone drained a month-long backlog:
**44 unique files, 65 uploads.** Most files were uploaded exactly twice.

The count also crept upward — one upload per cycle, then two per cycle
from 12:45:28 — consistent with each cycle getting slightly further
through the sequence before the failure landed.

## Why it fired that day

The client's read timeout is 30s (`RmailClient.kt`, `s.soTimeout =
30_000`). The daemon was blocked roughly 16s per cycle on an unreachable
contact (#377, and see #387), and phone requests queued behind that. 30s
was reachable, so a late step in the sequence timed out.

Note the interaction: #377 and #387 make this *rarer*, not fixed. Any
exception after the upload loop still discards the whole commit.

## Fix

Persist state incrementally, as each side effect is confirmed, rather
than batching one commit at the end. Recording a filename in the sync
state immediately after its upload returns success is enough to make this
class of duplicate impossible.

The general rule: state describing "what the server already has" should
be written when the server confirms it, not when the whole cycle
happens to finish.

## Explicitly not the fix

De-duplicating on the receiving end — by content hash or otherwise — is a
bandaid over a client that is re-sending work it already completed. It
also has a sharp edge: content-hash dedup would silently drop a
*legitimately* identical message, with no error to the sender. Fixing the
commit makes the duplicate never exist, so nothing has to be filtered.

## Status

Fixed in 01b0175 ("commit sync state incrementally"): every transfer
commits its own state the moment the server acknowledges it.  Kept open
only until the QA items are ticked; then move to completed/.
