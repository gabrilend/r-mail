# #346 — Attachment consent form: stale form persists and is regenerated for the wrong file

## Problem

Observed while sending two attachments back-to-back:

1. Sender sends attachment A (a picture). Recipient gets the consent
   form for A, accepts it, and the picture is delivered successfully.
2. After delivery, the consent form for A is **not removed** from the
   recipient's inbox. It should have been cleaned up.
3. Sender then sends attachment B (a music file). The expected new
   consent form for B does not appear. Instead, the existing (stale)
   consent form for A is **regenerated** — its `accept` / `deny` lines
   come back after the user had already deleted the `deny` line.
4. The regenerated consent form still has A's name and header details
   at the top, not B's.

So two bugs that may be one underlying bug:

- **Consent form not cleaned up** after the attachment it gated is
  delivered.
- **Second attachment's consent form never materialises**; instead the
  first form is rewritten to a default state with the first file's
  metadata.

## Investigation

- Check the code path that writes/rewrites
  `<name>-consent-to-download-form` files in the inbox.
- Check whether consent-state tracking keys files by sender + filename
  (so the second file would collide / overwrite) or by upload id.
- Verify that `check_consent_pending()` (or the equivalent) removes the
  consent file once the decision is acted upon.

## Expected behaviour

- Each incoming attachment creates its own consent form file, keyed so
  collisions with previous files are not possible.
- Once a consent form has been acted on (accept → delivered, deny →
  dropped), its file is removed.
- User edits to the consent form (e.g. deleting `deny`) are preserved
  and not overwritten by a later sync cycle.

## Source

From `issues/new-issue-please-sort`.

## Status

Completed. Fixes in `rmail.lua`:
- `handle_attachment_request` is idempotent on retries, keys the consent
  file by sanitized attachment filename (not outbox subject) with
  `att_id`-suffix disambiguation on collision, and fully sanitizes the
  incoming filename.
- `handle_attachment_chunk` rejects chunks with an unknown `att_id` and
  uses only the filename stored at request time — per-chunk
  `data.filename`/`data.subject` are no longer trusted.
- Completed, declined, and mid-transfer-cancelled transfers all remove
  the inbox consent/progress file.
- Mid-transfer cancel now also recognises the user writing a `deny`
  line, not just deleting the file. Detection lives in
  `consent_cancelled()` and runs in both the sync cycle and on each
  chunk.

Paired with narrow updates to #348 (PII window for attachment state is
now bounded to the active transfer period).

### Follow-up 2026-09-23: the form is named after its message

Keying the form by the attachment's name alone kept two attachments on
one message apart, but a photo named by a phone camera
(`20260903_154820.jpg`) produced a form named by a bare date, with nothing
saying which message it belonged to.  The owner agreed to name it after
the message first and the attachment second
(`dinosaur-hoodie-pic-20260903_154820.jpg-consent-to-download-form`), and
to add an `Attached to:` line inside.

`handle_attachment_request` looks the request's message id and sender up
in `inbox.json`, skipping consent entries, and uses the name the message
has in this inbox.  When the message is not in the record (deleted before
the request came), the form is named by the attachment alone, its
`Attached to:` line says the message is not in this mailbox's records, and
the log says so.  The ending `-consent-to-download-form` is unchanged, so
the phone (`Models.kt`, `isConsent`) and `helpers/raccept.sh` /
`helpers/rdeny.sh` still recognise forms.  The collision rule (a short
`att_id` prefix) still applies.  Covered by
`scripts/test-consent-form-name.sh`; the helper-scripts doc's example is
updated.
