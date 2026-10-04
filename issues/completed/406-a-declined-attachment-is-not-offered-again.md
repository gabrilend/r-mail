# #406 — Each recipient's answer about an attached file is kept

## Status

Completed 2026-10-04.  Found by the documents-against-code audit
(`notes/audit-docs-against-code-2026-10-02.md`, §1.1), checked by hand.
The owner: "Wa! That's a lot of terrible, terrible issues! Can we make
issue files for them?"  Designed with the owner on 2026-10-02 and
2026-10-04 (decisions quoted below).  Built together with #407, #408 and
#404f, which share its record.

## Current Behavior

The sender keeps, for every outbox message, every recipient and every
attached path, that recipient's **answer**.  A path is offered to a
recipient only while they have no answer for it, or their answer is
*withdrawn* and the line is back.

**Where the answers live** (decided 2026-10-02): in the outbox record
that already exists, `.state/outbox.json` — one entry per outbox file,
one section per recipient inside it — not in new files.  The owner asked
whether to use one file per recipient or one for all of them; one place
was chosen because the shared packed copy (#408) can be released only
when *every* recipient has an answer, and that question is asked of all
recipients at once.  Per outbox file:

| field | type | what it holds |
|---|---|---|
| `recipients[contact].message_id` | string | the id the message has on the recipient's side |
| `recipients[contact].body_checksum` | string (hex SHA-256) | the body they last answered for (#409) |
| `recipients[contact].attachments[path]` | string | their answer for that attached path, below |
| `recipients[contact].withdrawals[attachment id]` | string (the path) | a cancel owed to them (#407) |
| `packed[path]` | table | the one packed copy of the path: `zip` (string, its file), `checksum` (string), `total_chunks` (number), `expected_size` (number, bytes unpacked), `filename` (string, what recipients see) (#408) |

The answers:

| answer | set when | offered again? |
|---|---|---|
| *(none)* | not yet offered, or the offer is under way (a transfer record in `chunks-outgoing.json` says which) | — |
| complete | every piece was acknowledged | never |
| declined | the recipient said no | never |
| cancelled | one side stopped this one transfer: the recipient cancelled, their daemon refused it (oversize, damaged), they refused the offer itself, or the author removed their line from the `transfers` file | never |
| withdrawn | the author removed the `attach:` line while it was on its way to them | yes, if the line comes back |
| lost | the packed copy vanished from disk (#408) | not until the line is removed and put back |

**An answer belongs to the path, not to the file's contents** (decided
2026-10-02).  The owner: "let's do its path.  We shouldn't be able to
edit attachments, I don't think."  A recipient who declined
`attach: photo.jpg` is never offered `photo.jpg` again from that message.
This holds because what is sent is fixed when first offered (#408).

**Removing an `attach:` line withdraws the file** (decided 2026-10-02).
The owner: "deleting the line means you don't send anymore chunks to
anyone, and you send them a ping or something to an HTTP endpoint saying
'hey I'm not gonna send any more of: [attachment ID]'".  Each cycle, a
transfer of the message whose path is no longer attached for its
recipient is stopped: the answer becomes *withdrawn*, and if the offer
reached them (they may hold the form or pieces) a withdrawal — the
one-attachment cancel of #407, going the author's way — is owed to them,
retried on that contact's timer until their daemon answers.  Their
daemon removes the pieces and the form and leaves a `withdrawn-<file>`
note.  Recipients who already have the whole file keep it.  A recipient
whose whole `to:` line was removed is not sent a withdrawal: the removal
notice makes their daemon drop the message and everything attached.

**A withdrawal happens only when a sync cycle sees the line gone**
(decided 2026-10-04).  The owner, asked whether putting a removed line
back offers the file again: "yeah, if there was a sync cycle between the
two events."  Removed and put back between two cycles: nothing happened.
Put back after a cycle saw it gone: those whose answer is *withdrawn* are
offered it again as a new attachment (a new id; the packed copy if it is
still kept, otherwise packed from what is at the path then).

**A changed path is a different file** (decided 2026-10-04).  The owner,
asked whether someone who declined `old.jpg` should be offered `new.jpg`
when the author changes the line: "yeah it's a different file."
Changing the path is the old path withdrawn plus the new path offered.

## Intended Behavior

As above.  (rao-chat, which reads rmail as a rubric, records "refused"
per recipient in state for the same reason — its issue 216.)

## Suggested Implementation Steps

- `rmail.lua`, the `answers` table (beside the outbox markers; its head
  comment holds the record's layout): `recipient`, `record`,
  `record_now` (for code outside the outbox pass — the sync cycle runs
  between requests, never during one, so nothing else holds the record
  open), `stop` (record an answer and owe a withdrawal), `lost`,
  `sweep_pending` (#404f), `handle_cancel` (#407).
- `sync_outbox`: offers a path only to recipients without a settling
  answer; finds withdrawn paths by comparing each recipient's transfers
  with the paths their `to:` line still lists; turns *lost* into
  *withdrawn* once the line is gone (and takes the note away); queues
  owed withdrawals as `attachment_withdraw` operations; a refused offer
  is recorded *cancelled* rather than offered again every cycle.
- `handle_attachment_response` (a "no" is recorded), the chunk sender
  (complete, and a refusal mid-transfer), the transfers-file reader (the
  author's cancel for one recipient).
- Test: `scripts/test-attachment-answers.sh` — "a refusal is
  remembered" (declined, and 70 seconds later not asked again);
  "withdrawn, then offered again" (the form goes, a note says why, the
  answer is *withdrawn*; the line comes back and the recipient is asked
  again).
- Docs: attachments guide (the answers, sending, after your decision,
  cancelling), README (attachments), helper-scripts and defensive
  patterns (a declined file is not offered again).

## Related documents

- `notes/audit-docs-against-code-2026-10-02.md`
- `#407`, `#408`, `#404f` (built with this), `#409` (the same recipient
  section)
- `docs/.templates/attachments.md`
