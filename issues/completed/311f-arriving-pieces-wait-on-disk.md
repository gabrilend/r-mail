# #311f — Arriving attachment pieces wait on disk, not in RAM

## Status

Completed 2026-10-04.  Sub-issue of #311.  Written from rao-chat, which
reads rmail as a rubric and chose the same (rao-chat's issue 216b); the
owner asked for it: "can you make an issue file in r-mail describing the
concern, and suggest that we do it the same way?"

## Current Behavior

Attachments wait, while they travel, in the **pending folder**:
`attachment_pending_dir` in the mailbox's config, and by default
`<attachments>/.pending/` — a hidden folder inside the mailbox's own
attachments folder, on disk.  It holds:

- the pieces of an attachment arriving, in `.pending/<attachment id>/`
  (`chunk-0`, `chunk-1`, …), with the joined `assembled.zip` and the
  `extract/` folder it is unpacked into before the files move to
  `attachments/`;
- the packed copy of an attachment being sent, `rmail-<id>.zip`, which
  every recipient of that file gets (#314) and which is kept until every
  recipient has answered;
- the source of an oversized message body sent as an attachment (#308).

Because it is on disk:

- a transfer survives a restart or a reboot and resumes from the next
  piece still owed, with no new consent form;
- a large file does not first take room in RAM about three times over
  (pieces, joined zip, unpacked files) on its way to the disk where it
  ends up anyway;
- the packed copy that every recipient must get survives too, so it is
  never packed again from whatever is at the path by then.

Being hidden, nothing in it is listed among the received attachments or
sent to the phone (the folder lister skips names starting with a dot).

**At start-up** the daemon sweeps the folder: anything no record holds is
removed — pieces of a transfer whose consent record is gone, a packed
copy no message or transfer names — and each removal is logged.  Kept:
everything the consent records, transfer records and outbox record name,
which is how a transfer resumes.  The sweep runs only when the folder is
the default one: a folder set by hand may be shared by several mailboxes
(`/tmp`, the old default, often is), and another mailbox's files are not
this one's to judge.

`attachment_pending_dir` can still point somewhere in RAM.  A packed copy
lost there on a reboot is not packed again (#314): its transfers stop as
*lost*, with a note in the outbox file.

**Why it changed.**  The default used to be `/tmp`, with no recorded
reason.  On the owner's machine, as on many Linux systems, `/tmp` is a
RAM disk.  The concern in the other direction, the owner's (2026-10-02):
"I kinda want to put things that are untrusted on RAM too, because I
think they'd be easier to isolate. But maybe that's wrong."  It was
settled as rao-chat settled it (owner: "Let's leave the in-progress
attachments on disk ... suggest that we do it the same way"): what
isolates untrusted pieces is what #311 does to them — checksums before
anything is kept, the unpacked size counted before anything is made, no
links followed or created, names that cannot climb out of the folder —
not where they wait.  Nothing reads the pieces except those checks.

What stays in RAM: progress that means nothing after a reboot — the
progress files of #304.

## Intended Behavior

As above.

## Suggested Implementation Steps

- `rmail.lua`: `paths.pending` defaults to `paths.attachments ..
  "/.pending"` (the comment beside it says why); `answers.sweep_pending`,
  called from `init_runtime` after the mailbox's folders are made.
- Test: `scripts/test-attachment-answers.sh`, "a late recipient": the
  receiving mailbox names no pending folder, its pieces appear under its
  own `attachments/.pending/.pending/<id>/`, the sender's packed copy
  under its `attachments/.pending/`; the receiver is stopped part-way and
  started again, and the transfer finishes with no second consent form
  and without starting over.
- Docs: attachments guide ("Interrupted transfers", the configuration
  table).

## Related documents

- `issues/311-received-attachments-are-untrusted-input.md`
- `issues/completed/304-progress-files-in-ram.md`
- `issues/314-every-recipient-gets-the-attachment.md`
- `docs/.templates/attachments.md`
- rao-chat: `issues/completed/216b-the-receiving-side.md` (pieces in
  `attachments/.pending/<id>/` on disk: "files can be large; kept
  across restarts, so a transfer resumes")
