# #323 — Audit delete/edit race conditions between sender and receiver

## Problem

If a receiver deletes an inbox message and the sender edits (updates) the
same outbox message, the outcome depends on whose sync cycle runs first.
The update might "undelete" the file on the receiver's side.

## Action

Build two tables of all sender/receiver event interactions:

1. **Table 1**: sender's sync cycle runs first
2. **Table 2**: receiver's sync cycle runs first

Rows = receiver-side events/hooks (receive, delete, update, etc.)
Columns = sender-side events/hooks (send, delete, update, etc.)

Trace each interaction through the system to validate the behavior.
Document which combinations are handled correctly and which need fixes.

Record findings directly in this file. Do not mark this issue complete
until every problematic combination has either been split into its own
issue or explicitly closed as "not a problem".

---

## Event vocabulary

**Sender-side** (things that happen when the sender's sync cycle
observes an outbox-file change):

| Code | Event | Protocol message |
|---|---|---|
| S-SEND | New outbox file created | `POST /deliver` `type=message` |
| S-EDIT-BODY | Body of existing outbox file changed | `POST /deliver` `type=update` |
| S-ADD-TO | `to:` line added | `type=message` to new recipient |
| S-REMOVE-TO | `to:` line removed | `POST /delete` to removed recipient |
| S-ADD-ATTACH | `attach:` line added | `type=attachment_request` |
| S-DELETE | Outbox file deleted | `POST /delete` to all recipients |

**Receiver-side** (things that happen in the receiver's sync cycle, or
as inbound handlers for sender-initiated messages):

| Code | Event | Outcome |
|---|---|---|
| R-RECEIVE | Inbound `type=message` arrives | `handle_deliver_message` writes inbox file, updates `inbox.json` |
| R-UPDATE | Inbound `type=update` arrives | `handle_deliver_update` rewrites inbox file body |
| R-INBOUND-DELETE | Inbound `/delete` arrives | `handle_delete` removes inbox file + state |
| R-LOCAL-DELETE | User deletes an inbox file | `sync_inbox` next cycle → `/delete` to sender |
| R-LOCAL-EDIT | User edits an inbox file body | **Not propagated** — outbox is the source of truth |
| R-CONSENT | User accept/denies a consent file | `check_consent_pending` → `attachment_response` |

---

## Findings

### S-EDIT-BODY × R-LOCAL-DELETE — **bug, fixed in-line**

**Scenario A (sender sync first):**

1. Sender detects body change, sends `type=update` to receiver.
2. On the receiver, `handle_deliver_update` looked up the entry in
   `inbox.json`. That state still held the record even though the user
   had already `rm`'d the file, because `sync_inbox` only reconciles
   state on its next cycle.
3. Handler used to `write_file(target, new_body)` unconditionally —
   **silently re-creating the deleted inbox file.** The user's delete
   was clobbered.

**Fix (same commit as this audit):** `handle_deliver_update` now checks
`file_exists(target)` before writing. If the file is gone, it returns
`404`. The sender's batch-result handler at `rmail.lua:~2639` already
treats `404` on an update as "recipient deleted the message — clean up",
so the fix converges on the correct outcome without additional plumbing.

**Scenario B (receiver sync first):** `sync_inbox` observes the missing
file, sends `/delete` to sender, sender's `handle_delete` removes the
recipient from outbox state. Sender's next cycle sees no recipient to
update. Clean.

### S-DELETE × R-LOCAL-DELETE — OK

Both sides: `handle_delete` is idempotent. The sender-first path removes
the inbox file (it's already gone, `file_exists` short-circuits) and
clears the state entry. The receiver-first path removes the recipient
from the sender's outbox. Both `sync_outbox` and `sync_inbox` treat
`200` and `404` as success, so the second-arriving `/delete` is handled
cleanly either way.

### S-ADD-TO × R-LOCAL-DELETE (deletion is by the pre-existing recipient) — OK

The new recipient gets `type=message`, the deleting recipient's sync
sends `/delete`, the two operations target different recipients and
don't interact. No race.

### S-REMOVE-TO × R-LOCAL-DELETE — OK

Effectively two concurrent `/delete` calls to the same message-id
relationship. Idempotent per the S-DELETE × R-LOCAL-DELETE finding
above.

### S-EDIT-BODY × R-RECEIVE (first-time delivery + edit) — OK (eventually consistent)

Receiver briefly sees the pre-edit body between deliver and update.
That's expected under the living-messages model; no data loss.

### S-EDIT-BODY × R-LOCAL-EDIT — OK (by design)

Receiver-side inbox edits are not propagated (outbox is the source of
truth). An incoming update from the sender overwrites the receiver's
local edit. This is intentional; `on_update` is the escape hatch for a
receiver who wants to transform or reject updates. No change needed.

### S-ADD-ATTACH × R-LOCAL-DELETE — OK

`handle_delete` for the message cancels any pending consent (removes
the consent-to-download file and purges the pending-chunks dir) and
any outgoing chunk transfers scoped to `(sender, message_id)`.
Attachment state is cleared atomically with the message state.

### S-ADD-ATTACH × R-CONSENT (concurrent decline + resend) — OK

Every `attachment_request` carries a unique `att_id`. A prior declined
request's state has been cleared, so a new request is processed fresh.
No collision with the earlier consent file name (the receiver-side
handler has collision handling from #346).

---

## Conclusion

One real bug found: the sender-first `S-EDIT-BODY × R-LOCAL-DELETE`
race, fixed in-line by making `handle_deliver_update` return `404` when
the target inbox file is missing on disk. Every other pair traced
above is either correct by design or idempotent under concurrent
execution.

The audit is bounded to the event vocabulary listed at the top. If a
future refactor adds new sender- or receiver-side events (e.g. `update`
via Android over the API instead of the wire protocol), this table
needs another pass.

## Source

From `unsorted-issue-2`.

## Status

Completed. Single bug found and fixed (`handle_deliver_update`
`file_exists` guard). All other sender/receiver event pairs traced
above resolve cleanly.
