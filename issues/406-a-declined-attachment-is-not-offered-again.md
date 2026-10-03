# #406 — A declined attachment is not offered again

## Status

Open, 2026-10-02.  Found by the documents-against-code audit
(`notes/audit-docs-against-code-2026-10-02.md`, §1.1), checked by hand.
The owner: "Wa! That's a lot of terrible, terrible issues! Can we make
issue files for them?"  Belongs with attachments when #402 re-sorts the
phases.

## Current Behavior

When a recipient declines (deletes the form, or keeps only `deny`), the
sender's consent handler deletes the packed zip, writes
`inbox/declined-<file>` and drops the transfer record (rmail.lua, the
declined branch near "consent declined by").  Nothing removes the
`attach:` line from the outbox file — the only remover runs when a
transfer completes ("clean up completed transfers").  So on the sender's
next cycle `sync_outbox` finds an `attach:` line with no transfer and
sends a fresh `attachment_request` under a new id: the recipient gets a
new consent form every time the sender is due, for as long as the line
stays.

The attachments guide says the opposite (template 85-87: "the sender's
daemon removes the `attach:` line"; the form "replaced with a notice" —
it is removed).

## Intended Behavior

A refusal is remembered per recipient and per attached path: the file is
never offered to that recipient again, while other recipients are
unaffected.  The `attach:` line stays as the author wrote it (the outbox
file is the author's copy); what a recipient decided is kept in the
message's state.  (rao-chat, which reads rmail as a rubric, records
"refused" per recipient in state for this reason — its issue 216.)

## Suggested Implementation Steps

1. Keep each recipient's answer (declined, complete) in the outbox
   message's state, keyed by message id, then recipient, then the
   attached path.
2. `sync_outbox` offers a path to a recipient only when no answer is kept
   for that pair.
3. Test: a stand-in contact declines; three more sync cycles send no
   request; a second recipient still gets one.
4. Correct the attachments template (decline wording) and regenerate.

## Related documents

- `notes/audit-docs-against-code-2026-10-02.md`
- `#407`, `#408` (the other attachment-answer bugs)
- `docs/.templates/attachments.md`
