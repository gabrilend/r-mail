# #407 — Cancelling an attachment cancels the attachment, not the message

## Status

Open, 2026-10-02.  Found by the documents-against-code audit
(`notes/audit-docs-against-code-2026-10-02.md`, §1.2), checked by hand.

## Current Behavior

A receiver's cancellation of an attachment — the person cancelling, or
the daemon refusing it (oversize, a bad zip; `refuse_transfer`) — is sent
to the sender as `/delete` carrying the *message's* id (the cancellation
sender near `path = "/delete"`).  The sender's `handle_delete` cannot
tell that from "the recipient deleted the message": it strikes that
recipient's `to:` line, runs `on_delete`, and deletes the outbox file
when that recipient was the last one.  The recipient silently stops
getting later edits of the message, and the author may lose their own
outbox file.

The attachments guide says only "The sender's daemon is notified
automatically and stops sending" (template 238-239).

## Intended Behavior

A cancellation names the attachment, not the message: a message type of
its own (for example `attachment_cancel` with the attachment id).  The
sender stops that transfer for that recipient and records the answer
(#406's per-recipient record); the message, its `to:` lines and its
outbox file are untouched.

The same message also travels the other way (decided 2026-10-02, #406):
when the author removes an `attach:` line, the sender tells each
recipient who does not yet have the whole file that it will send no
more of that attachment id, and the recipient discards its pieces and
its consent form.  One message type, "this attachment id is cancelled",
sent by whichever side stopped; each side handles it by stopping that
one transfer, never by touching the message.  It goes through the
encrypted path like every other message, so the withdrawal itself names
nothing to an onlooker.

## Suggested Implementation Steps

1. A new encrypted request for cancelling one attachment, handled by the
   chunk sender's state, never by `handle_delete`.
2. `refuse_transfer` and the person's cancel send it; so does the
   sender, for each unfinished recipient, when an `attach:` line is
   removed (#406).  The receiving daemon handles it by deleting that
   id's pending pieces and its consent form, leaving a notice.
3. Test: a stand-in contact cancels mid-transfer; the sender's outbox
   file and its `to:` lines are unchanged; a later edit still reaches
   that contact; the attachment is not offered again.  Then the other
   way: the author removes the `attach:` line mid-transfer; the
   recipient's pieces and form are gone, a recipient who already had
   the file still has it, and an offline recipient is told when
   reached.
4. Correct the attachments template and regenerate.

## Related documents

- `notes/audit-docs-against-code-2026-10-02.md`
- `#406`, `#408`
