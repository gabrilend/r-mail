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

**Where the answers live** (decided 2026-10-02): in the outbox record
that already exists (`outbox.json`, one entry per outbox message, one
section per recipient inside it), not in new files.  Each recipient's
section gains one answer per attached path — offered, complete,
declined, cancelled — beside the message id it already holds.  #408 and
#409 add their per-recipient facts to the same section.  The owner asked
whether to use one file per recipient or one file for all of them; one
place was chosen because the shared packed copy (#408) can be released
only when *every* recipient has an answer, and that question is asked of
all recipients at once.

**An answer belongs to the path, not to the file's contents** (decided
2026-10-02).  The owner: "let's do its path.  We shouldn't be able to
edit attachments, I don't think."  A recipient who declined
`attach: photo.jpg` is never offered `photo.jpg` again, even if a
different picture now sits at that path.  This holds only if what is
sent is fixed when it is first offered: see #408 (the packed copy is
kept until every recipient has answered) and #404f (it is kept on disk,
so a reboot does not cause a fresh packing of whatever is on disk now).

**Removing an `attach:` line withdraws the file** (decided 2026-10-02).
The owner: "deleting the line means you don't send anymore chunks to
anyone, and you send them a ping or something to an HTTP endpoint saying
'hey I'm not gonna send any more of: [attachment ID]'".  So the outbox
file is read for what to send, not only kept as the author's copy:

- every recipient whose answer is not yet complete or declined (waiting
  on consent, or partway through receiving) stops getting pieces, and is
  sent a withdrawal naming the attachment id — the same one-attachment
  cancel message as #407, going the other way;
- the withdrawal is owed until that recipient's daemon answers it, and
  is retried on that contact's timer like an edit (#409); an offline
  recipient gets it when reached;
- the recipient's daemon throws away the pieces it holds for that id and
  replaces the consent form, or the progress notice, with a note that
  the sender withdrew the file;
- recipients who already have the whole file keep it; nothing is sent
  to them;
- each affected recipient's answer for the path becomes *withdrawn*; the
  packed copy is removed once no recipient still needs it (#408).

**A withdrawal happens only when a sync cycle sees the line gone**
(decided 2026-10-04).  The owner, asked whether putting a removed line
back offers the file again: "yeah, if there was a sync cycle between the
two events."  So:

- the line is removed and put back before any cycle reads the file —
  nothing happened; no withdrawal is sent, every answer stands;
- a cycle read the file without the line — the withdrawal above is
  owed, and the affected recipients' answer is *withdrawn*; when the
  line comes back, *withdrawn* does not block an offer: those
  recipients are offered the path again as a new attachment (a new id,
  packed from what is at the path then).  Recipients whose answer is
  complete or declined are not offered it again.

**A changed path is a different file** (decided 2026-10-04).  The owner,
asked whether someone who declined `old.jpg` should be offered `new.jpg`
when the author changes the line: "yeah it's a different file."
Changing the path is the old path withdrawn plus the new path offered to
every recipient; a decline of the old path says nothing about the new
one.

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
