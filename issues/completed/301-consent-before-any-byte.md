# #301 — No attachment moves before its recipient says yes

## Status

Completed — a blueprint written 2026-10-04 (#621) for what was built
before issue files described it.  The foundation of phase 3; #302
describes the pieces that follow a yes.

## Current Behavior

**The offer.**  Once a message's text has reached a recipient, each file
attached for them is packed once (#314) and offered:
`POST /deliver {type = "attachment_request", attachment_id, message_id,
filename, subject, expected_size}`.  The id is new for every offer; the
size is the file's unpacked size in bytes.  The sender records the
transfer (`.state/chunks-outgoing.json`: who, which message and path,
the packed copy, its checksum and piece count, `awaiting_consent`).

**The form.**  The receiver checks the id (hex digits and dashes only:
it names a folder, #311e) and the size (a whole number of bytes: both
size limits are built from it, #310), and writes a **consent form** into
its inbox, named after the message and the file
(`<message>-<file>-consent-to-download-form`, #305):

    alice wants to send you an attachment.

      Attached to:   photos-from-yesterday
      File:          photo.jpg
      Expected size: 3.2 MB
      Available:     47.3 GB on this drive
      After:         47.3 GB remaining (71% of capacity)

    Delete one line and leave your choice behind for the system to read:

    accept
    deny

A repeated offer of the same id leaves the form and the owner's half-made
choice alone.  The form is recorded in `consent-pending.json` (status
`pending`) and in the inbox record marked as a form, so the phone shows it
and deleting it is not taken for deleting mail.

**The answer.**  Each cycle the forms are read: only `accept` left —
yes; only `deny`, or the form deleted — no; both — still waiting, for as
long as the owner likes.  The phone can answer a form too
(`/api/consent`).  The answer is queued and sent —
`{type = "attachment_response", attachment_id, consent}` — retried until
the sender answers.  On a yes the sender sends pieces (#302) from its
next cycle; on a no it records the answer (#312) and leaves a
`declined-<file>` note in its own inbox.  **Nothing is taken before the
yes**: a piece for an unanswered or declined offer is refused unwritten
(#311e).

**While it arrives**, the form becomes a progress file — "Receiving
photo.jpg from alice — 87 / 200 chunks (43%)" — a link into the
machine's RAM folder, `/tmp/rmail-progress/`, so the rewrite after every
piece never touches the disk (#304).  Deleting it, or adding a `deny`
line, cancels the transfer (#313).  When the file is whole it is checked
and unpacked under #311's rules, saved in `attachments/` (a taken name
becomes `name-2.ext`; an identical file is kept once), the form is
removed, and `on_package` runs.

**On the sender's side**, the `transfers` file in the mailbox lists every
outgoing attachment: a section per file, a line per recipient,
"awaiting consent" or "5 / 12 chunks received".  It too lives in RAM.
Removing a recipient's line cancels their transfer; removing a section
cancels the file for everyone (#312).

## Intended Behavior

As above.

## Suggested Implementation Steps

1. `rmail.lua`: `sync_outbox` (the offer), `handle_attachment_request`
   (checks, the form), `check_consent_pending` (reading answers),
   `send_consent_responses`, `handle_attachment_response`, the chunk
   handler's consent gate; `write_progress_file` / `progress_tmpfs_path`
   (the RAM link), `consent_cancelled`, `remove_consent_form`;
   `write_transfers_file`, `check_transfers_file_cancellations`.
2. `helpers/raccept.sh`, `helpers/rdeny.sh` answer a form from a shell
   (#706).
3. Tests: `scripts/test-attachment-round-trip.sh`,
   `scripts/test-consent-form-name.sh`,
   `scripts/test-attachment-ids-and-consent.sh`,
   `scripts/test-attachment-answers.sh`.

## Related documents

- `docs/.templates/attachments.md`
- `#302`, `#310`, `#304`, `#706`, `#305`, `#311`, `#312`, `#313`, `#314`
