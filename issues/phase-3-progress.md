# Phase 3 Progress

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

## Counts

Current done and open counts per phase come from the dashboard; they are
not copied here, so they cannot go stale:

    /home/ritz/programming/ai-stuff/scripts/progress-dashboard.lua /mnt/mtwo/programs/r-mail -m

## Completed

Issues closed are listed here as they close, newest first, with one line
on what they gave the project.  Earlier phase-3 issues were closed before
this file existed; `issues/completed/3*.md` holds all of them.

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

## Open issues whose work is done but that are waiting on something

- **#374** (received files keep the sender's authoring time) — built and
  tested (`scripts/test-authoring-time.sh`); four open questions for the
  owner.
- **#375** (Android attachment picker) — built; its old open questions
  were settled by the later redesign but not confirmed by the owner.
- **#386** (Android sync state) — fixed; waits on checks on the phone.
- **#348** (personal information in state files, reversed) — rename steps
  now in the README; one decision left about healing old hashed records.
