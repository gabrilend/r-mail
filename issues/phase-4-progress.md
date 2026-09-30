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
