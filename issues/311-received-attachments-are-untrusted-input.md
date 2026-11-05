# #311 — A received attachment is untrusted input, and is checked as one

## Status

Open, 2026-09-29.  Listed with phase 3's attachments
(`phase-3-progress.md`).  It was first numbered 404 in phase 4, and its
sub-issues 404a–404f; they are #311 and #311a–#311f now.  The owner approved every fix below on 2026-09-29 ("yes,
everything that you mentioned"); #311e was found during the work and
added.

Done: #311a, #310 (reopened and closed), #311b, #311d, #311e, #311f —
each with its own test, all passing.  Open: #311c, whose daemon side is done and
tested but whose phone-app change has not been built (no Android SDK on
the machine it was written on).  Until the new app is installed, phone
uploads are refused.

## Current Behavior

A contact who holds a shared key can send an attachment: a request (file
name, declared size), the owner's consent, then numbered chunks of a zip
file, each carrying its own SHA-256 and the whole zip's SHA-256.  The
receiving daemon reassembles the zip in `<pending>/.pending/<id>/`,
extracts it into an `extract/` folder there, and files each entry into
`attachments/`.  The phone can read anything in `attachments/` through
`/api/attachments/<name>`, and the `on_package` hook is handed the path.

Every point below is now checked; the sub-issues describe how.  The
list is kept as the record of what a read of this path on 2026-09-29
found it trusting:

1. **Symbolic links.**  A zip can hold a link entry; `unzip` recreates it.
   A link named `photo` pointing at `~/.ssh/id_rsa` is filed into
   `attachments/`, and the phone (and the hook) then read the owner's
   private key through it.  A later entry in the same zip can also be
   written *through* a link made earlier.
2. **Unpacked size.**  Only the packed bytes are counted; a small zip can
   unpack into gigabytes (reopened as #310).
3. **Phone uploads.**  The unpacking step ignores whether `unzip`
   succeeded, joins every entry of a many-entry zip into one file, and
   never checks the chunk checksums the phone already computes.
4. **Missing checksums pass.**  A chunk with no checksum, or with no
   whole-file checksum, skips the check instead of being refused.
5. **Counts from the sender, each time.**  Every chunk says how many
   chunks there are and which one it is, and each is believed on its own.
   A file that changes while the sender is packing it is sent torn.

## Intended Behavior

Everything that arrives from a contact is treated as a claim until the
daemon has checked it:

- No link is ever created from a received zip.  In its place is a plain
  text note saying where the link pointed, so a person or an agent who
  wonders why something is missing finds the reason and can make the link
  by hand if it is valid.  Nothing in `attachments/` is served through a
  link.
- The unpacked size is measured before extraction (#310).
- A phone upload is verified chunk by chunk and as a whole, must be one
  file, and fails loudly when unpacking fails.
- Checksums are required, not optional.
- The number of chunks is fixed for a transfer, chunk numbers are checked,
  and a file that changes during packing is packed again.
- Found while doing this: attachment ids are used in folder names and in
  `rm -rf` without being checked, and chunks are accepted before the
  owner has said yes.  Both are fixed here too.

## Sub-issues

| ID | Name | Dependencies | Description |
|---|---|---|---|
| 311a | symbolic-links-become-notes | None | never recreate a link from a received zip; write a note instead; refuse to serve links |
| 310 | reject-oversized-transfers (reopened) | 311a | measure the unpacked size before extracting |
| 311b | chunk-checksums-and-counts-are-required | None | refuse chunks without checksums; fix the chunk count per transfer; check chunk numbers |
| 311c | phone-uploads-are-verified | 311a | per-chunk and whole-file checksums, one entry, unpacking checked (by the shared zip reader since #309) |
| 311d | files-changing-while-packed-are-packed-again | None | compare size and time before and after packing |
| 311e | attachment-ids-and-consent-are-checked-first | 311b | ids must look like ids; no chunk before consent |
| 311f | arriving-pieces-wait-on-disk | None | the pending folder defaults to a folder on disk, not `/tmp` (RAM on many systems); added 2026-10-02 |

Execution order: `311a → 310 → 311b → 311c → 311d → 311e → 311f`.  311a and 310
share the new unpacking step; 311b and 311e both change the chunk
handler, so they go one after the other.

## Suggested Implementation Steps

1. A stand-in contact for tests, `scripts/lib/fake-contact.lua`, that
   speaks rmail's encrypted request format with a shared key, so a test
   can send a real daemon things no honest daemon would; shared set-up for
   such tests in `scripts/lib/test-receiver.sh`.  Done.
2. The sub-issues in the order above, each with its own test script and
   commit.  Done except the phone build in #311c.
3. A control test, `scripts/test-attachment-round-trip.sh`: an honest
   attachment between two real daemons still arrives.  Done.
4. `docs/.templates/attachments.md` (the tracked source of
   `docs/attachments.md`): "What a received attachment is not allowed to
   do".  Done.

## Tests

    scripts/test-received-links.sh           #311a
    scripts/test-unpacked-size.sh            #310
    scripts/test-chunk-rules.sh              #311b
    scripts/test-phone-upload-checks.sh      #311c (daemon side)
    scripts/test-torn-pack.sh                #311d
    scripts/test-attachment-ids-and-consent.sh  #311e
    scripts/test-attachment-withdraw-and-resume.sh  #311f (pieces on disk across a restart)
    scripts/test-attachment-round-trip.sh    control: an honest transfer

Each builds its own throwaway mailboxes under `/tmp/rmail/tests/` on its
own port, so they can run together.

## Decisions (2026-11-05)

Made by the builder, checking this issue against the code on `main`.
The owner can overturn each one.

1. **Nothing is left to build here except #311c's phone side.**  Every
   point in Intended Behavior is in `rmail.lua` on `main`:
   - links are never made, and are never served (`upload.refuse_link`,
     and the listing leaves them out);
   - unpacking goes through the shared zip reader (#309), with the
     size limit (#310);
   - checksums and counts are required (#311b);
   - phone uploads are checked piece by piece, as a whole, and as one
     file (#311c, daemon side);
   - a file that changes while it is packed is packed again (#311d);
   - ids are checked and no piece comes before consent (#311e);
   - pieces wait on disk (#311f).

   The eight scripts under Tests all pass on `main` (run 2026-11-05,
   loopback only).  So the 2026-11-05 round adds no code.  It
   corrects this file and records the state.  Undo: none needed.
2. **#311 stays open until #311c is finished.**  The phone build needs
   the Android SDK and the owner's phone, so it was not touched.  The
   owner's 2026-09-29 approval still covers that step.  Undo: close #311
   now, and leave #311c open on its own.
3. **The phone stays refused until the new app is installed.**  The
   daemon refuses a resume without `total_checksum`, so the installed
   app's uploads fail with a 400.  Accepting them again would mean
   storing a whole zip that nobody checked, which is what #311 exists to
   stop.  So the refusal is kept, and #311c says so.  Undo: let
   `upload.checksums_from` accept a missing `total_checksum`, and have
   `upload.finish` skip the whole-file comparison when there is none.
   The owner would be giving up the whole-file check for old apps.
4. **The sub-issue table uses the current numbers.**  It still named the
   old 404a–404f and 327, which no file uses any more.  The
   Current Behavior list keeps its `unzip` wording, because it records
   what the 2026-09-29 read found; rmail has not run `unzip` since #309.

## Related

- #310 — reopened for the unpacked size.
- #307 — attachment pipeline audit (extract privately, then file).
- #823 — Android third-party outbox security (another trust boundary).
