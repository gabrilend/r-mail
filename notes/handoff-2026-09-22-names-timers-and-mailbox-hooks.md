# Handoff 2026-09-22 — names, timers, and the two mailboxes on this machine

Written by a session that started in `neocities-modernization` and drifted
into rmail work.  The owner moved the rmail thread here so its transcripts
live with this project.  The conversation itself is in
`/mnt/mtwo/programming/ai-stuff/neocities-modernization/llm-transcripts/sep-22-26.md`.

## Done and committed here

| Commit | What |
|---|---|
| 7efbdba | Contacts tidy-up after a sync; home-network search files an address under the local contact name (#393); separate self-address word (#394) |
| 671d098 | #394 reverted at the owner's request: `name` both labels the mailbox and means "me" on a `to:` line.  Kept #393 and the tidy-up.  Opened #395 (pinned) |
| 12861e4 | Search packets carry no name at all (incompatible; the owner is upgrading every machine).  A mailbox with no contacts keeps one timer of its own (#377 follow-up) |

Tests: `scripts/test-mailbox-selection.sh` and
`scripts/test-lan-discovery-names.sh` both pass.  The daemons running as
services (`kuvalu-mail` on 8025 for `~/mail`, `kuvalu-notes` on 8026 for
`~/notes/rmail`) need a restart (sudo, the owner does it) to run this code.

## Open, in this repository

- **#396** — outbox changes made during a sync lose their file-change
  notice and wait for a timer.  Question to the owner: honour them?
- **#395** — pinned: tell the owner when a contact names itself
  differently; never rewrite `contacts` unasked.
- **Main mailbox error loop.** `/tmp/kuvalu-mail.log` repeated
  "sync error: rmail.lua:302 (was :271) bad argument #1 to 'open' (string
  expected, got nil)" thousands of times, starting 14:02 right after
  "consent granted by sorelu for victory-garden.jpg".  A file-exists check
  is handed a nil path somewhere in the attachment path.  Not investigated
  further; likely #391 territory.  Check whether it survives the restart.

## Open, outside this repository (the owner's two mailboxes)

These were asked for in the same conversation and are not built yet.

1. **Terminal notice.**  `~/.bashrc` line 25 runs `/home/ritz/words/view-random`.
   Replace it with a call to a script in `/home/ritz/scripts/ai-stuff/`
   that, each time a terminal opens, counts files in `/home/ritz/mail/inbox/`:
   any at all → print "you have N new rmail messages at ~/mail"; none →
   run `view-random`.  Owner: every message in `~/mail/inbox/` counts as
   new; "we mark them as read by deleting or sorting them".  Decided at
   terminal start, so no hook edits `.bashrc`.
2. **Name-clash notice from the notes mailbox.**  The notes mailbox's
   `on_receive` hook (`/home/ritz/notes/rmail/hooks/on_receive.lua`) moves
   each arrival into `/home/ritz/notes/`.  When a note of that name already
   exists it leaves the message in the inbox and logs to
   `on_receive.log`.  Wanted: it also writes an outbox message addressed
   `to: kuvalu-mail` (the notes mailbox's contact name for `~/mail`) saying
   which file could not be sorted and to go fix it.  Plain text; no special
   treatment on arrival.  The contacts on both sides are set up and use
   `local-ip = 192.168.1.100`.  The design and its history are in
   `neocities-modernization/issues/10-068-*`, Open Question 1.

## Owner decisions worth keeping

- One config field (`name`) for both the label and self-addressing.
- Names in contacts are local; mail shows under the local name, never a
  name the sender supplies.  Renames are the owner's call.
- No backwards compatibility needed for the discovery packets.
- Errors, not fallbacks.
