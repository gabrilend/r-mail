# #307 — Attachment pipeline audit: frozen "zipping" line, invisible consent forms

## Status

Completed 2026-09-23.  Implemented 2026-09-22.

How it was verified:

- **Daemon (`rmail.lua`)**: every fix in the defect table and the two
  later sections was checked against the source by reading it.
  `scripts/test-stale-transfer-records.sh` (throwaway daemons, attachment
  transfer records in four states of disrepair) passed all cases on
  2026-09-23; it covers the sender's transfer bookkeeping that defect 3
  changed, not the consent or upload paths.  There is no automated test for
  consent-form recording, `/api/consent`, upload unpacking or name-clash
  filing.
- **Android**: verified by **reading the Kotlin source only**; nothing was
  built or run on a device for this check.
- **Restart**: the daemon changes need every daemon restarted.  Both
  daemons on kuvalu (`~/mail` and `~/notes/rmail`) were running code
  started 2026-09-23 08:47, after these changes landed.  sorelu is another
  machine and could not be checked from here.

## Current Behavior

### Consent forms

- A consent form written by `handle_attachment_request` is recorded in
  `inbox.json` with `consent = <att_id>` (message id `consent-<att_id>`),
  so `/api/sync` offers it to the phone like mail.  `check_consent_pending`
  backfills the record for forms that were already waiting from before.
- `remove_consent_form` deletes the form, its `/tmp/rmail-progress`
  symlink target, and its `inbox.json` entry, so the phone drops its copy
  on the next sync.
- `sync_inbox` treats an entry with `consent` as a form, not mail:
  deleting it declines the attachment (via `check_consent_pending`) and no
  delete notice goes to the sender.  Deleting one on the phone
  (`handle_api_sync`) logs "phone deleted consent form … (declines)".
- The phone answers with `POST /api/consent {filename, answer}`
  (`RmailClient.postConsent`, from `MainViewModel.answerConsent`).  The
  daemon finds the pending form by file name, deletes the line that was not
  chosen — exactly what a person at the machine would do — and makes the
  sender due now (`ctimer.get(from).next_due = 0`).  Bad answer: 400; no
  such pending form: 404.
- The phone recognises a form by its filename suffix
  `-consent-to-download-form` (`InboxEntry.isConsent` in `Models.kt`), not
  by content.
- `send_consent_responses` resolves responses addressed by a #505-era
  hashed name through `unmigrate_hashed_keys`; one that matches no contact
  is dropped with a log line; a refused response clears its form.
- `handle_attachment_response` (sender side) answers 404 "no such
  attachment transfer" when the transfer is gone, so the receiver clears
  the form instead of showing "being transferred" forever.

### Sending attachments

- A failed or skipped attachment request keeps the outgoing transfer with
  `request_sent = false` and re-asks next time with the same zip; only an
  explicit refusal (an HTTP status in reply) drops it.
- A new recipient's body is held in `sync_outbox` until every `attach:`
  path exists.  A missing path is marked in the outbox file
  (`mark_missing_attachment`); the marker is cleared when the file appears
  (`clear_missing_marker`).  Held files are counted as unresolved, so the
  "no recipients left" cleanup does not delete them.

### Phone upload model

1. Send copies each picked attachment into `pending-attachments/` in app
   storage (`MailStore.pendingAttachments`) and points the `attach:` line
   at the copy (`file://`).  The picker's `content://` grant dies with the
   process; our copy does not.
2. Each sync uploads pending attachments first
   (`SyncManager.uploadPendingAttachments` / `uploadOne`), rewriting the
   line to the server path.  A file with any phone-side `attach:`
   (`MailStore.localAttachRefs` / `isHeld`) is held off the server entirely
   until then.
3. Progress and failures show under the message in the outbox list
   (`UploadProgress`), never in the file.
4. Outbox files edited after upload are re-sent (per-file SHA-256 in sync
   state, `SyncState.outboxHashes`); the daemon passes the edit on as an
   update.
5. Syncs are serialised by a process-wide mutex (`SyncManager.syncLock`,
   shared by the app and the background worker).
6. A resumed upload trusts its chunk directory only if a `.complete`
   marker says splitting finished (`RmailClient.uploadFileCompressed`);
   otherwise the chunks are discarded and the file is zipped again.
7. The share intent writes the whole URI into the `attach:` line
   (`MainActivity.uriToAttachLine`), not `uri.path`.

### Files the phone sends appear in Files

- The phone zips a file before chunking it.  The daemon unpacks the
  finished upload (`unzip -p`, one entry, ignoring any path inside the
  archive) instead of storing the zip under the original name.
- Finished uploads are filed in `attachments/` itself — where the Files
  tab lists them — not hidden `.uploads/<id>/`.  Name clashes follow
  `upload.final_path`: identical content reuses the existing file;
  different content becomes `name-2.ext`.  The final path is only known
  once the content is, so it comes back with the last chunk (or from
  resume when nothing is missing).  The upload handlers are one `upload`
  table (`upload.start`, `upload.chunk`, `upload.resume`, `upload.finish`)
  because the main chunk is at Lua's 200-local ceiling.
- Phone: a picked file — Files tab `+`, or an attachment on a sent
  message — is copied into Files (`attachments/`, `MainViewModel.addToFiles`
  / `copyIntoFiles`), listed in `pending-uploads.json`
  (`MailStore.pendingUploads` / `setPendingUpload`), and uploaded by the
  next sync with no consent form (the phone is the mailbox's own device).
  After upload the local copy takes the server's name.  Files shows
  "waiting to upload" / progress / errors per file.  The checksum repair
  skips files still waiting, so it cannot "repair" a new file into a
  same-named server file.
- Files `+` used to open a message to this mailbox with the file attached;
  it now adds straight to Files.

### Received attachments no longer overwrite

A contact's attachment is extracted into the transfer's own pending
directory (`<pending>/extract`) first, then each entry is filed by
`upload.file_entry`, the same rule as phone uploads: identical content is
not duplicated, a differing file becomes `name-2.ext`, and a folder
attachment is never merged into an existing folder (`album-2`).  The rename
is logged ("name taken, saved as …") and passed to the `on_package` hook as
the real path.  Before, it was unzipped straight into `attachments/` with
`unzip -o`, silently replacing any file of the same name — including files
uploaded from the phone.

## Intended Behavior

A message sent from the phone with an attachment reaches its recipient as
the body plus a consent form, the form reaches the recipient's phone, and
answering it (on the phone or at the machine) moves the attachment.
Nothing about an upload's progress is ever written into the message.  A
failure anywhere is visible where the person looks, and retried rather than
silently dropped.  A file never arrives as a zip wearing the original's
name, and no arriving file silently replaces another.

### The symptom that started this

A received message ended with `zipping 20260518_114051.jpg... 0.1 MB / 6.2 MB`
and never changed.  No consent form ever arrived; none was ever answered.

### Root cause (one path explains all three symptoms)

The Android app wrote upload progress *into the outbox file* while zipping,
and uploaded each outbox file to the daemon exactly once, on first sight.
A sync that ran mid-zip shipped the file with the progress line in it; the
daemon delivered that as the body.  The attachment upload then failed into
an empty `catch`, so the `attach:` line still named a `content://` URI the
daemon cannot open.  No zip, no attachment request, no consent form.

Not a recent regression -- the code dates from aabd3e3 ("Streaming
uploads").  It surfaced during the Aug-Sep address outage, when uploads
failed.

### Other defects found and fixed

| # | defect | fix |
|---|---|---|
| 1 | Consent forms never reached the phone: not recorded in `inbox.json`, which is all `/api/sync` offers | recorded with `consent = <att_id>`; backfilled for forms already waiting; `remove_consent_form` drops the entry; `sync_inbox` treats forms as forms (deleting one declines; no /delete to the sender) |
| 2 | Phone Accept/Deny wrote "accept" into a new *outbox* file with no recipient | `POST /api/consent {filename, answer}` edits the server's form and makes the sender due |
| 3 | A failed/skipped attachment request deleted the transfer and its zip, so every cycle re-zipped on the main loop (every contact merely not-due since #115) | transfer kept with `request_sent = false` and re-asked with the same zip; only an explicit refusal (HTTP status) drops it |
| 4 | Consent responses addressed by a #505-era hash matched no contact and waited forever, silently | resolved via `unmigrate_hashed_keys`; unmatched ones dropped with a log line; a refused response clears its form |
| 5 | Body delivered before attachments existed | new-recipient delivery held until every `attach:` path exists; the missing marker is cleared when the file appears; held files are exempt from the "no recipients left" cleanup (which would otherwise have deleted them) |
| 6 | Phone guessed consent forms from content (any line "accept"/"deny") | by filename suffix `-consent-to-download-form` |
| 7 | Sender answered "ok" to a response for a transfer it no longer had, leaving the receiver "being transferred" forever | 404 |
| 8 | Share intent wrote `uri.path` (no scheme, unopenable) as the attach line | whole URI |
| 9 | Resumed uploads trusted a chunk set cut short by the app being killed | `.complete` marker; incomplete sets are discarded |

Found while doing this (2026-09-22): every file sent from the phone had
reached its recipients as a zip named `.jpg`.  All 24 files then in
`~/mail/attachments/.uploads/` were such zips.

### Cleanup done 2026-09-22

- Frozen progress line stripped from `~/mail/outbox/pic-in-dinosaur-hoodie`
  and from the phone's copies of it and of `rmail-critical-inconsistency`.
  Their `content://` attachments are unreadable now; the phone says so and
  they need re-attaching by hand.
- The July `victory-garden.jpg` accept (hashed to kuvalu) is left for the
  new code to resolve and send; if kuvalu no longer has the transfer, it
  refuses and the form is cleared.  (By 2026-09-23 it no longer appears in
  kuvalu's `consent-responses.json`.)

## Suggested Implementation Steps

Daemon, `rmail.lua`:

1. `handle_attachment_request`: write the form, and record it in
   `inbox.json` with `from`, `message_id = "consent-<att_id>"`,
   `consent = <att_id>`.  `check_consent_pending`: backfill that record for
   any pending form that lacks one.  `remove_consent_form`: also drop the
   `inbox.json` entry.
2. `sync_inbox`: an entry with `consent` is a form — when its file is gone,
   drop the entry; send no delete notice.  `handle_api_sync`: a phone-side
   delete of a form declines it.
3. HTTP dispatch: `POST /api/consent` as described under Current Behavior.
4. `send_consent_responses`: resolve hashed addressees with
   `unmigrate_hashed_keys`; drop and log unmatched ones; a refusal clears
   the form.
5. `handle_attachment_response`: 404 when the transfer is unknown.
6. `sync_outbox` attachment-request results: success sets
   `request_sent = true`; an HTTP status that refuses drops the transfer;
   anything else keeps it with `request_sent = false` for the next cycle.
7. `sync_outbox` new-recipient delivery: hold until every attachment path
   exists (`mark_missing_attachment` / `clear_missing_marker`), and add the
   file to the unresolved set so the cleanup pass leaves it.
8. A shared `upload` table: `final_path(filename, tmp)` (free name, or the
   identical existing file, or `name-N.ext`, by SHA-256), `file_entry(src,
   name)` (file or folder, never merging folders), and the upload handlers
   `start`, `chunk`, `resume`, `finish` — `finish` unzips a `PK\3\4`
   upload with `unzip -p` and files it by `final_path`, returning the final
   path.
9. Received attachments: extract into `<pending>/extract`, file each entry
   with `upload.file_entry`, log renames, pass the real path to
   `on_package`.

Android, `clients/android/app/src/main/kotlin/com/rmail/app/`:

10. `data/MailStore.kt`: `pendingAttachments` directory,
    `pending-uploads.json` (`pendingUploads`, `setPendingUpload`),
    `freeAttachmentName`, `localAttachRefs` / `isHeld`, `outboxHash`.
11. `sync/SyncManager.kt`: `sync()` under the companion `syncLock` mutex;
    `uploadPendingAttachments` before outbox upload; hold files with local
    `attach:` lines; re-send outbox files whose hash changed
    (`computeChangedOutbox`, `backfillOutboxHashes`); report through
    `UploadProgress` and `uploadFailed`, never into the file.
12. `sync/UploadProgress.kt`: a process-wide map from outbox file to
    status text, shown under the message in the outbox list.
13. `net/RmailClient.kt`: `postConsent`; the `.complete` marker in
    `uploadFileCompressed`; take the final server path from the last chunk
    or resume.
14. `data/Models.kt`: `isConsent` by filename suffix.
15. `ui/MainViewModel.kt`: `answerConsent` → `postConsent`;
    `addToFiles` / `copyIntoFiles`; skip checksum repair for pending
    uploads.
16. `ui/MainActivity.kt`: share intent writes `attach: <whole URI>`.
17. Tests: `scripts/test-stale-transfer-records.sh` for transfer records.
    Restart every daemon after changing `rmail.lua`, and rebuild the APK
    (`scripts/compile-android.sh`).

## Related

- [[820-android-attachment-picker-bottom-sheet]] — the picker whose
  results feed the upload model above.
- #505 (hashed contact names in state), #115 (per-contact timers).
