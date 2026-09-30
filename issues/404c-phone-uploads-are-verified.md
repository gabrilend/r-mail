# #404c — A phone upload is verified piece by piece and as a whole, and must be one file

## Status

Open, 2026-09-29.  Sub-issue of #404.

## Current Behavior

The phone sends a file to its home mailbox like this
(`RmailClient.uploadFileCompressed`, Kotlin):

1. zip the file (one entry, the file), cut the zip into 256 KiB pieces;
2. `POST /api/upload/resume` with the file name, the number of pieces and
   the SHA-256 of each piece (`chunk_checksums`, keyed by index);
3. `PUT /api/upload/<id>/chunk/<n>` for each piece the daemon lacks.

The daemon (`upload.resume`, `upload.chunk`, `upload.finish`):

- uses the piece checksums in `resume` only to throw away pieces already
  on disk that do not match; it does not keep them, so `upload.chunk`
  stores whatever bytes arrive, unchecked;
- has no checksum of the whole zip at all;
- in `finish`, runs `unzip -p <zip> > unpacked` and checks only that
  `unpacked` exists — which it always does, because the shell creates it
  before `unzip` runs, so a failed unzip files an empty or partial file;
- joins every entry of a many-entry zip end to end into one file.

`/api/upload/start` also exists; the phone no longer calls it.

## Intended Behavior

- `resume` (and `start`) require a SHA-256 for every piece and a
  SHA-256 of the whole zip (`total_checksum`), 64 hex characters each;
  otherwise 400.  They are stored in the upload's record.  A resume with
  different checksums than the record (the phone zipped again) replaces
  them, and pieces on disk are re-checked against the new ones.
- `chunk` checks each piece against its stored checksum before writing
  it; a mismatch is refused with 400 and nothing is written.
- `finish` checks the assembled zip against `total_checksum`; a mismatch
  discards the upload and answers 500 with the reason.
- The zip must hold exactly one entry, and it must be a regular file (not
  a folder or link); otherwise the upload is refused.
- `unzip`'s exit status is checked; a failure is an error, and the
  half-written file is removed.
- Phone: `uploadResume` sends `total_checksum`, the SHA-256 of the pieces
  joined in order (the zip), computed from the piece files so it works on
  a resumed upload too.

## Suggested Implementation Steps

1. `upload.checksums_from(data, num_chunks)` — validates and returns the
   piece table and total checksum, or an error.
2. `upload.start`, `upload.resume`: use it; store `chunk_checksums`,
   `total_checksum` in the record.
3. `upload.chunk`: verify before writing.
4. `upload.finish`: whole-zip checksum; `upload.list_entries` (from #404a)
   for the one-regular-file rule; `unzip -p` through `upload.succeeded`.
5. Kotlin, `clients/android/.../net/RmailClient.kt`: compute and send
   `total_checksum` in `uploadResume`.  Build with
   `scripts/compile-android.sh --test` if the toolchain is present;
   otherwise say that the client change is untested.
6. Test `scripts/test-phone-upload-checks.sh`: the stand-in contact acts as
   the owner's phone (`own = true`): missing checksums → 400; a piece that
   does not match → 400; a two-entry zip → refused; a zip whose unzip fails
   (a corrupted entry with a correct outer checksum) → refused, nothing
   filed; an honest upload → filed with the right content.

## Related

- Parent: #404.  Uses the listing helper from #404a.
- #391 — introduced unpacking phone uploads.
