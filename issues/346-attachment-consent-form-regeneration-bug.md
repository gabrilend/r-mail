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
