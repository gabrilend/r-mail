# Phase 4 Progress

Phase 4 exists because phase 3 ran out of numbers: every number from 300
to 399 is taken.  On 2026-09-23 the decoy-traffic issue, which shared the
number 314 with another issue, was renumbered 401 and became phase 4's
first issue.

## Open question

What is phase 4 about?  Phases group related functionality rather than
record time, so phase 4 wants a theme.  Two ways it could go:

- a real theme that decoy traffic fits, such as privacy against people
  watching the network (decoy traffic, wire-level padding, bodies sent as
  padded attachments), with the related phase-3 issues moved here; or
- a different numbering shape for new issues, leaving phase 4 as a
  one-issue overflow.

2026-09-23: the owner chose to re-sort every issue into up to nine themed
phases before release, together with writing blueprints for everything
built without one.  Planned in #402 and deferred until then; until it
runs, new issues that do not fit elsewhere continue here.

## Counts

    /home/ritz/programming/ai-stuff/scripts/progress-dashboard.lua /mnt/mtwo/programs/r-mail -m

## Completed

Newest first, with one line on what each gave the project.

- **2026-10-04 — #406, #407, #408, #404f: each recipient's answer about an
  attached file is kept, and every recipient gets the same file.**  A file
  is no longer offered again to someone who has it or said no; a recipient
  reached late still gets it, from the one packed copy made when it was
  first offered, kept on disk until everyone has answered; removing an
  `attach:` line withdraws it, and putting it back after a sync offers it
  again; a cancel names the attachment and no longer reads as deleting the
  message; arriving pieces wait on disk inside the mailbox and survive a
  restart.  Covered by `scripts/test-attachment-answers.sh` (against
  stand-in recipients, `scripts/lib/fake-recipient.lua`) and
  `scripts/test-attachment-withdraw-and-resume.sh`.

- **2026-10-04 — #409 an edit is retried until it is delivered.**  Each
  recipient keeps the checksum of the version it last took; an edit made
  while a contact was not due or offline used to be lost for good.
  Covered by `scripts/test-edit-delivery.sh`, which also caught a crash in
  the address handler for a contact known only by its key (fixed).

- **2026-10-04 — #410 the plain health check names no one.**  It answers
  `{"ok":true}`; the mailbox's name had come along by accident when
  encryption moved out of TLS.  Covered by
  `scripts/test-plaintext-health-check.sh`.

- **2026-10-04 — #411 saving contacts from the phone keeps the file's
  comments.**  Only the contacts that changed are edited; the merged file
  must read back as what the phone sent.  Covered by
  `scripts/test-phone-contacts-save.sh`.

- **2026-09-29 — #404e attachment ids are checked, and nothing is taken
  before the owner's yes.**  A contact chose the id that names a
  transfer's folder, which is later removed with `rm -rf`; an id climbing
  out with `../` pointed that at folders outside rmail's.  Only rmail's own
  id shape is taken now, and a piece sent before the owner accepts is
  refused.  Covered by `scripts/test-attachment-ids-and-consent.sh`.
  Still open under #404: #404c (phone uploads) waits on building the
  Android app.

- **2026-09-29 — #404d a file written to while it is packed is packed
  again, not sent torn.**  Each file's size and modification time are
  taken before and after zip reads it; any difference throws the zip away
  and leaves the attachment for the next cycle.  zip's exit status is now
  read correctly on LuaJIT too.  Covered by `scripts/test-torn-pack.sh`.

- **2026-09-29 — #404b every attachment piece carries its checksums, and
  the piece count is fixed per transfer.**  A piece without checksums is
  refused; piece numbers must be whole and in range; the count, the whole
  zip's checksum and the piece length are pinned when piece 0 arrives,
  and a later piece that disagrees is not stored.  A claim of a million
  pieces no longer makes the receiver count to a million.  Covered by
  `scripts/test-chunk-rules.sh`; an honest two-mailbox transfer by
  `scripts/test-attachment-round-trip.sh`.

- **2026-09-29 — #404a a symbolic link in a received zip becomes a note.**
  A contact's zip could plant a link to any file on the computer (a
  private key, say) in `attachments/`, and the phone read through it.
  Links are now left out of extraction and replaced by a
  `<name>.symlink.txt` note saying where they pointed; a search after
  extracting refuses any that slip through; the phone is never served a
  link.  Also fixed: the phone's attachment listing crashed whenever a
  folder was in `attachments/`.  Covered by
  `scripts/test-received-links.sh`.  Part of #404 (received attachments
  are untrusted input), which is still open.

- **2026-09-29 — #403 the JSON library's choice of decoder is no longer
  silent.**  The bundled dkjson's switch to its faster LPeg decoder
  crashed on every modern LPeg and fell back to plain Lua without a word;
  it now works with old and new LPeg, keeps the reason when it does not
  switch, and the daemon logs which decoder it is on at start-up.  An
  absent LPeg is stated, not an error (LPeg is not an rmail dependency).
  Covered by `scripts/test-json-decoders.sh`.  Filed here only because
  phase 3 is full; it moves with start-up and dependencies under #402.

- **2026-09-30 — #405 zips are packed and read by the shared zip
  library.**  rmail no longer runs `zip` or `unzip`.  A copy of the shared
  library (my-libs/zip, also rao-chat's) in `libs/` packs attachments and
  reads every received zip.  It checks the whole structure before making
  a byte (names that climb out, overlapping entries, devices, damage),
  counts every byte before it is made, and never makes a link.  This
  replaces #404a's link listing, #327's `unzip -p` byte count and #404c's
  `unzip -p`.  Phone uploads gain a bound: the claimed size must fit the
  free space.  Until compression exists, attachments travel uncompressed
  (larger on the wire).  Covered by every attachment test and the new
  `scripts/test-zip-library.sh`, which also fails when the copy drifts
  from the library.
