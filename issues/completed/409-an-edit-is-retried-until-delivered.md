# #409 — An edit is retried until it is delivered

## Status

Completed 2026-10-04.  Found by the documents-against-code audit
(`notes/audit-docs-against-code-2026-10-02.md`, §1.4), checked by hand;
#374's "Found while verifying" section reported the same.

## Current Behavior

When the author edits an outbox file that has already been sent, every
recipient is owed the new version, and stays owed until that recipient's
daemon answers the update.

The outbox record (`.state/outbox.json`, one entry per outbox file, one
section per recipient inside it) keeps, in each recipient's section, a
`body_checksum`: the SHA-256 (hex string) of the outbox body that
recipient last answered for.  It is written:

- on a successful first delivery, with the checksum of the outbox body
  (the author's text — even when an oversized body travels as a stub and
  an attachment, #349);
- on a successful update, with the checksum the update carried;
- at once, for the author's own copy (a message to oneself is written
  straight into the inbox, so nothing can be missed).

Each cycle, `sync_outbox` takes the outbox body's checksum and builds an
update for every recipient whose kept checksum differs.  A recipient not
due on their timer (#377) or not reachable keeps the old checksum, so the
update is built again next cycle and goes out when the contact is due.
Only the newest version is ever sent; intermediate edits made while a
contact was away are not replayed.  A 404 answer (the recipient deleted
the message) removes that recipient from the record, as before.

There used to be one checksum per outbox file, saved while the updates
were being built and before any was sent.  Records written before this
change are carried over: a recipient with no checksum of its own takes
the old file-wide one, once, and the file-wide field is then dropped.

## Intended Behavior

As above: an edit counts as delivered to a recipient only when that
recipient answered it, and is retried on that contact's timer until then.

## Suggested Implementation Steps

- `rmail.lua`, `sync_outbox`: the body-edit pass compares each
  recipient's `body_checksum` with the body's; the deliver and update
  operations carry the checksum they send; the results pass writes it
  into the recipient's section only on success.
- Test: `scripts/test-edit-delivery.sh` — two real mailboxes.  The
  message arrives; it is edited at once while the contact is not due,
  and the edit must arrive when the timer runs out; then the receiver is
  stopped, the message edited again, the sender fails to reach it and
  backs off, the receiver returns and speaks first (which makes the
  sender's timer for it due again), and the second edit must arrive.
  Run against the code before this change, the not-due case fails: the
  receiver keeps the first version.
- Docs corrected: README (living messages), scripting tutorial
  (`on_update`), defensive patterns (heartbeat cost).

## Related documents

- `notes/audit-docs-against-code-2026-10-02.md`
- `issues/374-preserve-sender-creation-time-as-received-mtime.md`
- `#377` (per-contact timers)
- `#406`, `#408` (attachment answers kept in the same recipient section)
