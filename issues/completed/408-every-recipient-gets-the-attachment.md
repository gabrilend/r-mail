# #408 — Every recipient gets the same attachment, however late they are reached

## Status

Completed 2026-10-04.  Found by the documents-against-code audit
(`notes/audit-docs-against-code-2026-10-02.md`, §1.3), checked by hand.
Built together with #406, #407 and #404f.

## Current Behavior

The `attach:` line stays as the author wrote it.  Each recipient is
offered each attached path until they have an answer for it (#406),
whenever they are reached: someone offline while the others finish is
offered the file when they come back.

**Attachments cannot be edited once offered** (owner, 2026-10-02: "We
shouldn't be able to edit attachments, I don't think").  The first time
a path is offered in a message it is packed once, and the packed copy is
recorded in the message's outbox record (`packed[path]`: the zip's file,
its checksum, its piece count, the unpacked size, the name recipients
see).  Every later offer of that path in that message — another
recipient, a recipient reached late, a withdrawn one offered again while
the copy is kept — uses that copy.  The path is never packed a second
time while the copy is kept, so a file changed or deleted after the
first offer does not change what anyone receives.

The packed copy lives in the pending folder, on disk inside the mailbox
(#404f), so it survives a reboot.  It is kept while any recipient still
needs it — one whose `to:` line lists the path and who has no answer yet
(not offered, or the offer under way), or whose answer is *withdrawn*
(to be offered again).  Recipients who cannot be sent to (not a contact,
or marked with an error) do not hold it.  When none needs it, the copy is
removed and logged; it also goes with the message's record when the
outbox file is deleted or finished with.

**A lost copy is not rebuilt.**  If the packed copy is gone from disk
(someone removed it, or the pending folder was set to RAM and the machine
rebooted), packing the path again would send later recipients different
bytes.  Instead (`answers.lost`): every transfer of it stops with the
answer *lost*, recipients who may hold its form or pieces are sent a
withdrawal (#407), recipients not yet answered are marked *lost*, the log
says so as an error, and a note is written under the `attach:` line:
`// ATTACHMENT LOST: <path> — its packed copy is gone; remove the
attach: line, wait for one sync, and put it back to send it again`.
Removing the line turns *lost* into *withdrawn* and takes the note away;
putting it back offers the file again, packed from what is there then.
An oversized message body sent as an attachment (#349) is the one case
still rebuilt from its source: it is the message's own text.

**Before**: when the first recipient finished, the `attach:` line was
removed, and a recipient whose transfer did not yet exist got the text
and never the file.  The packed copy was shared only while some transfer
held it, then deleted, and it lived in `/tmp` (RAM on the owner's
machine): a recipient reached later, or anyone after a reboot, got a
fresh packing of whatever was at the path then.

## Intended Behavior

As above.

## Suggested Implementation Steps

- `rmail.lua`, `sync_outbox`: offering from `packed[path]` (packing only
  when there is none); the release pass after the withdrawal pass;
  `drop_packed` when a message's record goes; completed transfers no
  longer touch the outbox file (the line remover, its only use gone, was
  removed).  `release_zip` now deletes only an auto-body zip (#349).
  `send_next_chunks` records *complete* and calls `answers.lost` instead
  of packing again.
- Tests: `scripts/test-attachment-answers.sh`, "a late recipient gets the
  same file" — three real mailboxes; bob is offline while alice receives
  the file; the file is replaced on disk; bob, reached later, receives
  alice's bytes; the `attach:` line is still there; the packed copy is
  kept until bob has answered and removed after.
  `scripts/test-stale-transfer-records.sh` — transfer records whose packed
  copy is missing are stopped, not rebuilt, and no cycle crashes.
- Docs: attachments guide (sending, transfer mechanics, interrupted
  transfers), README (attachments).

## Related documents

- `notes/audit-docs-against-code-2026-10-02.md`
- `#406`, `#407`, `#404f`
