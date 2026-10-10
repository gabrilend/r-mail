# #316 — A file attached to several messages is packed once, not once per message

## Status

Completed 2026-10-09.  Test: `scripts/test-shared-packed-copy.sh`.

Filed 2026-10-04 from the ritzmenardi.com shrine, whose mail robot
(`/mnt/mtwo/backups/ritzmenardi.com/tools/rmail-robot.lua`) sends one
9 GB zip from one mailbox to many people.  The shrine's server has 25 GB
of disk (its conversation of 2026-10-04,
`/mnt/mtwo/backups/ritzmenardi.com/llm-transcripts/oct-4-26.md`, "The
Nanode's numbers").  Given to the r-mail session to finish, 2026-10-09
(the owner: "these are yours now ... if they aren't done, then finish
them").

## Current Behavior

**Built 2026-10-09.**  A packed entry records the file's `fingerprint`
(read just before packing).  A message's first offer of a path asks
`answers.shared_copy`: another message's entry for that path, with the
fingerprint the file has now and its zip still on disk, is copied into
this message's entry instead of packing, and the log says "sharing the
packed copy of <path> with <message> (unchanged since packed)".  The
two places that deleted a copy — the release pass in `sync_outbox`
(every recipient has answered) and `drop_packed` (the message is gone) —
ask `answers.zip_in_use` first: while another message's entry names the
zip, only this entry goes, logged "released ... another message still
uses it".  A file changed between two offers gets a fresh copy; the
earlier message keeps its own.  A lost copy is found lost by each message
that names it, at its next offer.  The attachments guide describes it.

`scripts/test-shared-packed-copy.sh`, one real sender and a stand-in
recipient: two messages attaching one file leave one copy on disk, named
by both records; one message's declined offer keeps the copy, the
second's removes it; a file changed between offers gives two copies; a
message deleted while sharing leaves the copy for the other.  On the
previous code five of its eight cases fail (two copies).

**Before 2026-10-09:** when a path is first offered in a message it is packed once, and the
packed copy belongs to that message: it is recorded in the message's
outbox record (`packed[path]` in `.state/outbox.json`, #314) and lives in
the pending folder until no recipient of that message needs it.  Every
later recipient of the same message gets the same copy, which is right.

But a second message that attaches the same path packs it again, into a
second copy, and so does a third.  For small files this is harmless.  For
a large one it multiplies the disk the sender needs: the shrine sends a
9 GB zip, and every outbox message that carries it would hold its own
9 GB copy while anyone on it is still downloading.

The robot works around it today by putting everyone who asks into one
shared message per zip version instead of a message each, which keeps the
copies to one per version, at the cost of everyone on a message seeing
the same text.  (Waiting-list and welcome messages, which carry no
attachment, are per person.)

## Intended Behavior

A packed copy belongs to the file as it was when packed, not to a
message.  Any message offering the same path, while the file is the same
as when it was packed, uses the same copy.  The copy is kept while any
recipient of any message still needs it, and removed when the last one
is done.

"The same file" is the existing fingerprint test that #311d already
makes (`upload.fingerprint`: every file under the path with its size and
modification time, read before and after packing): an attachment whose
path and fingerprint match an existing copy uses that copy; a changed
file is packed anew, as now.  #314's promise is kept: within a message,
everyone gets the bytes that were first offered, even if the file changes
later.  (This settles the question the issue first held — share only
while unchanged, or keep each message's first copy: both, since a message
never gives up the copy it offered, and a new message only shares a copy
that still matches the file.)

## Suggested Implementation Steps

The record keeps its shape: each message still has its own `packed[path]`
entry.  Two entries may name the same zip file, and that sharing is the
whole change — no new table, no migration of existing records.

1. A packed entry gains `fingerprint` (the text `upload.fingerprint`
   returns), read just before packing.  Entries written before this
   change have none and are never shared.
2. `answers.shared_copy(state, path)`: another message's entry for the
   same path whose fingerprint equals the file's fingerprint now and whose
   zip is still on disk; its fields are copied into this message's entry
   instead of packing (in `sync_outbox`, where a first offer packs).
3. `answers.zip_in_use(state, zip, except_name)`: whether any other
   message's entry names that zip.  The two places that delete a packed
   copy — the release pass in `sync_outbox` ("every recipient has
   answered") and `drop_packed` (the message is gone) — remove only the
   entry when another message still names the zip, and delete the file
   only when none does.  `answers.sweep_pending` already keeps every zip
   any entry names.
4. A lost copy (#314's `answers.lost`) is lost for every message that
   used it: each message finds its entry's zip missing at its next offer
   and takes the lost route itself.
5. Test `scripts/test-shared-packed-copy.sh`: two outbox messages attach
   the same file; one copy in the pending folder, named by both records;
   finishing one message keeps it; finishing both removes it; a file
   changed between the two offers gives two copies.

## Related

- #314 — every recipient of a message gets the same packed copy.
- #311d — the fingerprint test that says a file changed while packed.
- #317 — sending a single file without any packed copy at all.
