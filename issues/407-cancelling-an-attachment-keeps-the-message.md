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

## Suggested Implementation Steps

1. A new encrypted request for cancelling one attachment, handled by the
   chunk sender's state, never by `handle_delete`.
2. `refuse_transfer` and the person's cancel send it.
3. Test: a stand-in contact cancels mid-transfer; the sender's outbox
   file and its `to:` lines are unchanged; a later edit still reaches
   that contact; the attachment is not offered again.
4. Correct the attachments template and regenerate.

## Related documents

- `notes/audit-docs-against-code-2026-10-02.md`
- `#406`, `#408`
