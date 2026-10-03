# #408 — Every recipient gets the attachment, however late they are reached

## Status

Open, 2026-10-02.  Found by the documents-against-code audit
(`notes/audit-docs-against-code-2026-10-02.md`, §1.3), checked by hand.

## Current Behavior

When any recipient's transfer completes, the "clean up completed
transfers" pass removes the shared `attach:` line from the outbox file
(`remove_attach_from_file`).  Transfers for a recipient are created only
after that recipient's body has been delivered.  So with `to: alice`,
`to: bob` and an attached file, if bob is unreachable while alice
finishes, the line is gone before bob's transfer exists: bob gets the
text and never the file.

The attachments guide says "Both alice and bob get photo.jpg" (template
23).

## Intended Behavior

The `attach:` line stays as the author wrote it.  Each recipient has its
own record (#406): a recipient is offered the file until it is complete
or answered for them, whenever they are reached.  The packed zip is
removed only when every recipient's record is complete or answered.

## Suggested Implementation Steps

1. Drop the removal of `attach:` lines on completion; mark the recipient
   complete in the message's state instead.
2. Remove the packed zip when no recipient still needs it.
3. Test: two stand-in contacts, one unreachable; the first completes; the
   second, reached later, is offered and receives the file.
4. Correct the attachments template (the line is not removed) and
   regenerate.

## Related documents

- `notes/audit-docs-against-code-2026-10-02.md`
- `#406`, `#407`
