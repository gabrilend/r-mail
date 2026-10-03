# #409 — An edit is retried until it is delivered

## Status

Open, 2026-10-02.  Found by the documents-against-code audit
(`notes/audit-docs-against-code-2026-10-02.md`, §1.4), checked by hand;
#374's "Found while verifying" section reports the same.

## Current Behavior

`sync_outbox` notices an edited outbox file by its body checksum, builds
an `update` for each recipient, and saves the new checksum
(`state[name].body_checksum = current_checksum`) while building — before
anything is sent.  If the contact is not due (the per-contact timer gate
skips the request) or cannot be reached, the update's failure is only
logged ("other failures: roll into the unreachable summary"); next cycle
the checksum already matches, so the edit is never sent again.  The
recipient keeps the old version for good.

The scripting tutorial (template 70-76, 351-352) and the heartbeat
pattern (defensive template 60-121) promise that edits arrive.

## Intended Behavior

An edit counts as delivered to a recipient only when that recipient
answered it.  The checksum each recipient last received is kept per
recipient; an update is owed to every recipient whose kept checksum
differs from the file's, and is retried on that contact's timer until it
succeeds (or the recipient answers 404, deleted).

## Suggested Implementation Steps

1. Keep `body_checksum` per recipient in the outbox state, written when
   that recipient's update succeeds.
2. `sync_outbox` builds updates for recipients whose kept checksum
   differs.
3. Test: a stand-in contact is unreachable while the author edits; when
   it comes back, the edit arrives; an edit made while the contact is
   not due arrives when it is.
4. Until fixed, the README and tutorial say edits can be lost.

## Related documents

- `notes/audit-docs-against-code-2026-10-02.md`
- `issues/374-preserve-sender-creation-time-as-received-mtime.md`
- `#377` (per-contact timers)
