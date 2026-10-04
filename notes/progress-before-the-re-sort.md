# Progress before the phase re-sort (to October 2026)

Until 2026-10-04 the issues sat in four phases that recorded roughly when
they were filed rather than what they were about: phase 3 held a hundred
issues on every subject, and phase 4 was its overflow.  On 2026-10-04
(#402) every issue was renumbered into nine themed phases, and each
phase's progress file is now generated from the issue files
(`scripts/generate-phase-progress.lua`).  The four hand-written progress
files are kept here, as they stood, because their entries say what each
piece of work gave the project in words the issue files do not repeat.
Issue numbers written as `#NNN` or as file names were rewritten to the
new numbers with everything else; bare numbers in the tables (`| 100 |`)
are the old ones — `notes/phase-renumbering-2026-10.map` translates them.

---

## Phase 1 Progress

Phase 1 focuses on reliability and usability improvements for LAN-based communication.

### Goals

- Improve same-LAN peer discovery and connectivity
- Fix edge cases in attachment handling
- Enhance user experience for common workflows

### Issues

| ID | Description | Status |
|----|-------------|--------|
| 100 | Lua 5.4 os.execute compatibility | ✓ Completed |
| 101 | Tilde expansion in attach: paths | ✓ Completed |
| 102 | UDP LAN discovery protocol | ✓ Completed |
| 103 | Function ordering: remove_recipient_from_file | ✓ Completed |

### Completed

All Phase 1 issues have been resolved. Issue files moved to `completed/` directory.

### Notes

- Phase 1 issues were identified during debugging of same-LAN connectivity where hairpin NAT was not supported
- Issue 100 was the root cause of attachment failures - compression/extraction succeeded but return value check failed on Lua 5.4

---

## Phase 2 Progress

Phase 2 focuses on shared device support, multi-device mailbox access, and codebase maintainability.

### Goals

- Enable laptops and secondary devices to sync with home daemon
- Implement attachments transfer file for shared device downloads
- Support outbox relay through home daemon
- Modularize codebase to avoid Lua upvalue limits

### Issues

| ID | Description | Status |
|----|-------------|--------|
| 200 | Shared device sync access | Will not implement |
| 201 | Modularize rmail.lua codebase | Open |
| 202 | Fix chunk response parsing | Fixed |
| 203 | LAN discovery improvements | Fixed |
| 204 | Fix partial send for large payloads | Fixed |
| 205 | Redirect service logs to /tmp | Fixed |

### Completed

- **202**: Fixed chunk response parsing - added status to http_post_batch results, fixed data access in send_next_chunks
- **203**: LAN discovery improvements - include LAN IP in payload, multicast + subnet scan fallback, NixOS path fixes
- **204**: Fixed partial send bug in http_encrypt_and_send - large payloads (attachment chunks) were getting truncated because send() wasn't looping. This was the root cause of "chunk failed" errors.
- **205**: Redirect service logs to /tmp (RAM-backed) - prevents startup messages from blocking TTY login prompt, avoids disk wear. Added view-logs.sh script and hidden .logs symlink.
- **200**: Will not implement - After design review, granular device permissions add too much complexity for unclear use cases. The laptop-at-library scenario can use the Android app. Daemon-to-daemon sync would require new code and raises unanswered questions about copy/move/mirror semantics.

### Notes

- Phase 2 originally aimed to enable shared device sync, but after design review this was deferred
- The remaining focus is codebase maintainability (issue 201)
- Laptop sync use case can be addressed with Android app for now
- Issue 201 addresses the Lua 60-upvalue limit by splitting into modules

---

## Phase 3 Progress

Phase 3 is everything built on the stable two-daemon base from phases 1
and 2: day-to-day mail between people and their own devices.  It grew into
the project's working phase and holds its widest spread of issues:

- **Delivery and sync** — living messages that follow edits, per-contact
  timers and backoff, the sync cycle's shape (#377, #397), stale-state
  recovery.
- **Attachments** — consent before transfer, chunked sending, wildcards
  and quoting in `attach:` lines (#362, #363), the pipeline audit (#391).
- **Addresses** — several addresses per contact, home-network discovery,
  announcing address changes, periodic public-address checks.
- **The Android client** — the phone as an outbox and inbox for a home
  mailbox.
- **Installation and many mailboxes** — one service per mailbox, the
  mailbox as the installation (#381, #382), portable drives.

Phase 3 used every number from 300 to 399.  New issues that would belong
here need a decision about numbering first; see `phase-4-progress.md`.

### Counts

Current done and open counts per phase come from the dashboard; they are
not copied here, so they cannot go stale:

    /home/ritz/programming/ai-stuff/scripts/progress-dashboard.lua /mnt/mtwo/programs/r-mail -m

### Completed

Issues closed are listed here as they close, newest first, with one line
on what they gave the project.  Earlier phase-3 issues were closed before
this file existed; `issues/completed/3*.md` holds all of them.

- **2026-09-29 — #327 reopened and closed again: the unpacked size is
  enforced.**  A transfer already could not take more packed bytes than
  its declared size allows; now the bytes its zip unpacks to are measured
  (really decompressed into a counter, nothing written) against the same
  limit before extraction, so a small zip cannot unpack into gigabytes.
  A declared size of 0 no longer switches the limit off, and a request
  without a size is refused.  Covered by `scripts/test-unpacked-size.sh`.
  Part of #404 (received attachments are untrusted input).

- **2026-09-23 — #362 wildcards in `attach:` lines** and **#363 outbox
  header robustness.**  `attach: ~/pics/*.jpg` becomes one line per file;
  blank lines inside the header, quoted paths and `~` paths all read the
  same way; a missing file gets a note in the outbox file that clears
  itself when the file appears.  Three defects found while closing them
  were fixed first; covered by `scripts/test-outbox-headers.sh`.
- **2026-09-23 — #381 one service per mailbox.**  Several mailboxes on
  one machine each get their own service, named after the mailbox or
  chosen with `--service-name`; the log viewer and ignore rules follow
  any name.  Parts of it were later replaced by #382 (the mailbox is the
  installation), recorded step by step in the issue.
- **2026-09-23 — #391 attachment pipeline audit.**  Phone uploads can no
  longer ship a half-written message; consent forms reach the phone and
  are answered from it; a failed request keeps its zip instead of
  re-zipping every cycle; nine defects in all.

### Open issues whose work is done but that are waiting on something

- **#374** (received files keep the sender's authoring time) — built and
  tested (`scripts/test-authoring-time.sh`); four open questions for the
  owner.
- **#375** (Android attachment picker) — built; its old open questions
  were settled by the later redesign but not confirmed by the owner.
- **#386** (Android sync state) — fixed; waits on checks on the phone.
- **#348** (personal information in state files, reversed) — rename steps
  now in the README; one decision left about healing old hashed records.

---

## Phase 4 Progress

Phase 4 exists because phase 3 ran out of numbers: every number from 300
to 399 is taken.  On 2026-09-23 the decoy-traffic issue, which shared the
number 314 with another issue, was renumbered 401 and became phase 4's
first issue.

### Open question

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

### Counts

    /home/ritz/programming/ai-stuff/scripts/progress-dashboard.lua /mnt/mtwo/programs/r-mail -m

### Completed

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
