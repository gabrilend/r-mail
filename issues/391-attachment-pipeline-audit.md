# #391 — Attachment pipeline audit: frozen "zipping" line, invisible consent forms

## Symptom

A received message ended with `zipping 20260518_114051.jpg... 0.1 MB / 6.2 MB`
and never changed.  No consent form ever arrived; none was ever answered.

## Root cause (one path explains all three symptoms)

The Android app wrote upload progress *into the outbox file* while zipping,
and uploaded each outbox file to the daemon exactly once, on first sight.
A sync that ran mid-zip shipped the file with the progress line in it; the
daemon delivered that as the body.  The attachment upload then failed into
an empty `catch`, so the `attach:` line still named a `content://` URI the
daemon cannot open.  No zip, no attachment request, no consent form.

Not a recent regression -- the code dates from aabd3e3 ("Streaming
uploads").  It surfaced during the Aug-Sep address outage, when uploads
failed.

## Other defects found and fixed

| # | defect | fix |
|---|---|---|
| 1 | Consent forms never reached the phone: not recorded in `inbox.json`, which is all `/api/sync` offers | recorded with `consent = <att_id>`; backfilled for forms already waiting; `remove_consent_form` drops the entry; `sync_inbox` treats forms as forms (deleting one declines; no /delete to the sender) |
| 2 | Phone Accept/Deny wrote "accept" into a new *outbox* file with no recipient | `POST /api/consent {filename, answer}` edits the server's form and makes the sender due |
| 3 | A failed/skipped attachment request deleted the transfer and its zip, so every cycle re-zipped on the main loop (every contact merely not-due since #377) | transfer kept with `request_sent = false` and re-asked with the same zip; only an explicit refusal (HTTP status) drops it |
| 4 | Consent responses addressed by a #348-era hash matched no contact and waited forever, silently | resolved via `unmigrate_hashed_keys`; unmatched ones dropped with a log line; a refused response clears its form |
| 5 | Body delivered before attachments existed | new-recipient delivery held until every `attach:` path exists; the missing marker is cleared when the file appears; held files are exempt from the "no recipients left" cleanup (which would otherwise have deleted them) |
| 6 | Phone guessed consent forms from content (any line "accept"/"deny") | by filename suffix `-consent-to-download-form` |
| 7 | Sender answered "ok" to a response for a transfer it no longer had, leaving the receiver "being transferred" forever | 404 |
| 8 | Share intent wrote `uri.path` (no scheme, unopenable) as the attach line | whole URI |
| 9 | Resumed uploads trusted a chunk set cut short by the app being killed | `.complete` marker; incomplete sets are discarded |

## Phone upload model now

1. Send copies each picked attachment into `pending-attachments/` in app
   storage and points the `attach:` line at the copy (`file://`).  The
   picker's content:// grant dies with the process; our copy does not.
2. Each sync uploads pending attachments first, rewriting the line to the
   server path.  A file with any phone-side `attach:` is held off the
   server entirely until then.
3. Progress and failures show under the message in the outbox list
   (`UploadProgress`), never in the file.
4. Outbox files edited after upload are re-sent (per-file SHA-256 in
   sync state); the daemon passes the edit on as an update.
5. Syncs are serialised by a process-wide mutex (app + worker).

## Cleanup done 2026-09-22

- Frozen progress line stripped from `~/mail/outbox/pic-in-dinosaur-hoodie`
  and from the phone's copies of it and of `rmail-critical-inconsistency`.
  Their `content://` attachments are unreadable now; the phone says so and
  they need re-attaching by hand.
- The July `victory-garden.jpg` accept (hashed to kuvalu) is left for the
  new code to resolve and send; if kuvalu no longer has the transfer, it
  refuses and the form is cleared.

## Files the phone sends appear in Files (2026-09-22)

- **Found while doing this:** the phone zips a file before chunking it and
  the server concatenated the chunks and stored the *zip* under the
  original name.  Every file sent from the phone reached its recipients as
  a zip named `.jpg`.  All 24 files in `~/mail/attachments/.uploads/` are
  such zips.  The server now unpacks the upload (`unzip -p`, one entry,
  ignoring any path inside the archive).
- Finished uploads are filed in `attachments/` itself -- where the Files
  tab lists them -- instead of hidden `.uploads/<id>/`.  Name clashes:
  identical content reuses the existing file; different content becomes
  `name-2.ext`.  The final path is only known once the content is, so it
  comes back with the last chunk (or from resume when nothing is missing).
  The three upload handlers became one `upload` table (200-local ceiling).
- Phone: a picked file -- Files tab `+`, or an attachment on a sent
  message -- is copied into Files (`attachments/`), listed in
  `pending-uploads.json`, and uploaded by the next sync with no consent
  form (the phone is the mailbox's own device).  After upload the local
  copy takes the server's name.  Files shows "waiting to upload" /
  progress / errors per file.  The checksum repair skips files still
  waiting, so it cannot "repair" a new file into a same-named server file.
- Files `+` used to open a message to this mailbox with the file
  attached; it now adds straight to Files.

## Status

Implemented 2026-09-22.  Daemon changes need a restart of every daemon
(sorelu and kuvalu).
