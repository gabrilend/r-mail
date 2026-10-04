# #313 — Cancelling an attachment cancels the attachment, not the message

## Status

Completed 2026-10-04.  Found by the documents-against-code audit
(`notes/audit-docs-against-code-2026-10-02.md`, §1.2), checked by hand.
Built together with #312, #314 and #311f.

## Current Behavior

Stopping one attachment transfer is its own encrypted message,
`/deliver` with `{"type": "attachment_cancel", "attachment_id": …}`
(the message id rides along for the log, unused).  It names the
attachment, never the message, and whichever side receives it stops that
one transfer and nothing else.  Which way it is going is told apart by
which record holds the id:

- **We are sending it to them** (the id is in `chunks-outgoing.json`,
  addressed to the contact who sent the cancel): they cancelled, or their
  daemon refused the transfer.  The transfer record is removed and their
  answer becomes *cancelled* (#312).  The message, its `to:` lines, its
  outbox file and their place on it are untouched; later edits still
  reach them.
- **They are sending it to us** (the id is in `consent-pending.json`,
  from that contact): the author withdrew it (#312).  The pieces held for
  it and its consent form or progress file are removed, a
  `withdrawn-<file>` note is left in the inbox, and an answer to the form
  still waiting to go out is dropped.
- **Neither**: 404.  Both sides read any answer (ok, 404, or a refusal
  from a daemon too old to know the message) as settled — asking again
  would not change it — and only no answer at all as "retry when the
  contact is next due".  A refusal is logged as a warning naming an older
  rmail as the likely cause; such a sender may keep sending pieces, which
  are refused.

Who sends it:

- the receiving daemon, when the person cancels (deletes the progress
  file, or adds a `deny` line) or when its own checks refuse a transfer
  (`upload.refuse_transfer`): `send_attachment_cancellations`, for every
  consent record marked `cancel_pending`;
- the sending daemon, for every withdrawal owed (`withdrawals` in the
  recipient's section of the outbox record): when the author removes an
  `attach:` line, removes a recipient from the `transfers` file, or a
  packed copy is lost.

It goes through the encrypted path like every other message, so the
cancel names nothing to an onlooker.

**Before**: a receiver's cancel was sent as `/delete` carrying the
*message's* id.  The sender's delete handler could not tell that from
"the recipient deleted the message": it struck their `to:` line, ran
`on_delete`, and deleted the outbox file when they were the last
recipient.

## Intended Behavior

As above.

## Suggested Implementation Steps

- `rmail.lua`: `answers.handle_cancel` (both directions), dispatched
  from `handle_deliver` as `attachment_cancel`;
  `send_attachment_cancellations` sends it instead of `/delete`;
  `sync_outbox` builds an `attachment_withdraw` operation per owed
  withdrawal and clears it on any answer.
- Test: `scripts/test-attachment-answers.sh` — "a cancel stops the file,
  not the message": acting as the recipient, the test cancels an offer;
  the sender's outbox file is byte for byte unchanged, the answer is
  *cancelled*, an edit of the message still reaches the recipient, and
  the file is not offered again.  "withdrawn, then offered again" covers
  the author's direction.
- Docs: protocol guide (`/delete`, the message-type table), attachments
  guide (cancelling, as sender and receiver).

## Related documents

- `notes/audit-docs-against-code-2026-10-02.md`
- `#312`, `#314`, `#311f`
