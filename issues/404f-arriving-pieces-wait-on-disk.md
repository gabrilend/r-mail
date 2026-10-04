# #404f — Arriving attachment pieces wait on disk, not in RAM

## Status

Open, 2026-10-02.  Sub-issue of #404.  Written from rao-chat, which
reads rmail as a rubric and chose differently here (rao-chat's issue
216b); the owner asked for it: "can you make an issue file in r-mail
describing the concern, and suggest that we do it the same way?"  Not
built.

## Current Behavior

The pieces of an attachment being received wait in
`<attachment_pending_dir>/.pending/<attachment id>/` (`rmail.lua`: the
`pending` path, `config.attachment_pending_dir or "/tmp"`; the chunk
handler around "all chunks present: reassemble").  The same folder holds
the joined `assembled.zip` and the `extract/` folder it is unpacked into,
before the files move to `attachments/`.  The default is `/tmp`.

On the owner's machine `/tmp` is a RAM disk (tmpfs, 15.5 GB), as on many
Linux systems.  So by default:

- **Memory**: a large attachment occupies RAM while it arrives, and at
  its peak about three times over — the pieces, the joined zip, and the
  unpacked files, side by side — for a file that will end up on disk
  anyway.  A few large transfers at once, or one near the RAM disk's
  size, can fill it, and with it everything else that uses `/tmp`.
- **Reboots**: the pieces vanish on a reboot, so a transfer starts over
  from its first piece (`docs/.templates/attachments.md`, "Interrupted
  transfers": "the OS clears partial downloads on reboot").
- **No recorded reason** for `/tmp` as the default: the guide presents it
  as a trade-off, and no issue records why it was picked.

The concern in the other direction, the owner's (2026-10-02): "I kinda
want to put things that are untrusted on RAM too, because I think they'd
be easier to isolate. But maybe that's wrong."  Received pieces are
untrusted input until checked (#404).  RAM is gone on a reboot, is not
backed up, and keeps a half-received, unchecked file away from the
drive where the person's files live.

## Intended Behavior

Pieces wait on disk by default, in a folder of the mailbox's own (next
to `attachments/`, e.g. `attachments/.pending/`), as rao-chat does
(owner: "Let's leave the in-progress attachments on disk ... suggest
that we do it the same way").  A setting may still point it at RAM for
someone who wants that.  Because:

- a file that will be kept on disk anyway does not first need room in
  RAM three times over;
- a transfer survives a reboot and resumes where it stopped, with no new
  consent (the rest of the protocol already resumes);
- what isolates untrusted pieces is what #404 already does to them —
  checksums before anything is kept, the unpacked size measured before
  extraction, no links followed or created, names that cannot climb out
  of the folder — not where they wait.  Pieces on disk are no more
  trusted than pieces in RAM: nothing reads them except the checks.

The same folder also holds the *outgoing* packed copies (the packer
writes `rmail-<id>.zip` into `paths.pending`).  Since attachments cannot
be edited once offered (#408), that copy is the one every recipient must
get, so it too must survive a reboot: it moves to disk with the pieces.

What stays in RAM: progress that means nothing after a reboot — the
progress files of #328, which stay as they are.

## Suggested Implementation Steps

1. The default of `attachment_pending_dir` becomes a folder inside the
   mailbox (beside `attachments/`), made at start-up; `/tmp` stays
   possible by setting it.
2. Leftover `.pending/<id>/` folders found at start-up are kept (that is
   how a transfer resumes); one whose transfer is gone (cancelled,
   refused, the message deleted) is removed, as today.
3. `docs/.templates/attachments.md` ("Interrupted transfers", the
   configuration table) says the new default and why.
4. Tests: a transfer interrupted by restarting the daemon resumes from
   the next missing piece with no new consent; the pending folder is
   inside the mailbox by default; an explicit `/tmp` setting still works.

## Related documents

- `issues/404-received-attachments-are-untrusted-input.md`
- `issues/completed/328-progress-files-in-ram.md`
- `docs/.templates/attachments.md`
- rao-chat: `issues/completed/216b-the-receiving-side.md` (pieces in
  `attachments/.pending/<id>/` on disk: "files can be large; kept
  across restarts, so a transfer resumes")
