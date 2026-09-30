# #404c — A phone upload is verified piece by piece and as a whole, and must be one file

## Status

In progress, 2026-09-29.  Sub-issue of #404.  The daemon side is built
and covered by `scripts/test-phone-upload-checks.sh` (all cases pass;
against the code before this change, 10 of its cases fail).  The phone
side is written but **not built or run**: this machine has no Android SDK,
so `scripts/compile-android.sh --test` could not run.  What remains:
build the app, install it, and send a file from the phone once.

**Until the new app is installed, uploads from the phone fail**: the
daemon now refuses a resume without `total_checksum`, which the installed
app does not send.  The daemon logs nothing for this (the refusal is a
400 answer); the phone shows its usual upload failure.

## Current Behavior

The phone sends a file to its home mailbox like this
(`RmailClient.uploadFileCompressed`, Kotlin):

1. zip the file (one entry, the file), cut the zip into 256 KiB pieces
   (kept in a chunk folder with a `.complete` marker, so an interrupted
   upload resumes with the same pieces);
2. `POST /api/upload/resume` with the file name, the number of pieces,
   the SHA-256 of each piece (`chunk_checksums`, keyed by the piece number
   as a string) and — new — the SHA-256 of the whole zip
   (`total_checksum`), computed by feeding the piece files in order
   through one digest, so a resumed upload has it too;
3. `PUT /api/upload/<id>/chunk/<n>` for each piece the daemon lacks.

The daemon (`rmail.lua`, the `upload` table):

- `upload.checksums_from` requires a valid checksum (64 hex digits) for
  every piece and a valid `total_checksum`; otherwise 400.
  `upload.resume` and `upload.start` both use it, and store them in the
  upload's record in `uploads.json`:

  | field | type | meaning |
  |---|---|---|
  | `chunk_checksums` | table, piece number (string) → hex string | each piece's SHA-256 |
  | `total_checksum` | hex string | the whole zip's SHA-256 |

  A resume always replaces them (a phone that zipped again has new ones)
  and re-checks the pieces already on disk against them, dropping those
  that do not match.
- `upload.chunk` checks each piece against its recorded checksum before
  writing it; a mismatch is refused with 400 and nothing is written.  A
  record with no checksums (made before this change) answers 409 "resume
  it first".
- `upload.finish` checks the assembled zip against `total_checksum`, then
  requires exactly one entry, a regular file (`upload.list_entries` from
  #404a), then runs `unzip -p` and reads its exit status
  (`upload.succeeded`).  Any refusal goes through `upload.discard`: the
  upload's pieces and record are removed, the reason is logged, and the
  last piece is answered 500 with the reason.  An upload that is not a
  zip is refused. It used to be filed as it was. The owner (2026-09-29):
  *"we want to successfully and completely defeat every single one of the
  zip dangers, so let's try and zip everything we send over the network.
  Less bandwidth."* Every upload goes through one checked path, and the
  phone always zips anyway.

### Before this issue (the problems it solved)

- Piece checksums were only used by `resume` to drop stale pieces already
  on disk; a piece arriving afterwards was stored unchecked.
- There was no whole-file checksum.
- `unzip -p <zip> > unpacked` was followed by "does `unpacked` exist?",
  which is always true — the shell creates the file before unzip runs —
  so a failed unzip filed an empty or partial file.
- A zip holding several files was joined end to end into one file.

## Intended Behavior

Every piece and the whole are checked against checksums the phone
declared; the zip is one regular file; a failed unzip is an error.  The
phone app sends the whole-file checksum.

## Suggested Implementation Steps

1. Daemon — done: `upload.checksums_from`, `upload.discard`; checksums in
   `upload.start` / `upload.resume`; the per-piece check in
   `upload.chunk`; the whole-file check, one-regular-file rule and checked
   unzip in `upload.finish`.
2. Phone — written, not built:
   `clients/android/app/src/main/kotlin/com/rmail/app/net/RmailClient.kt`,
   `uploadResume(..., totalChecksum)` and the digest over the pieces in
   `uploadFileCompressed`.  (`uploadStart` is not called by the app; it
   now needs checksums too and was left as it is.)
3. **Remaining:** `scripts/compile-android.sh --test` on a machine with the
   Android SDK; install; upload one file from the phone and see it in
   Files.  Then mark this issue complete.
4. Test `scripts/test-phone-upload-checks.sh` — done, passing.
5. `docs/.templates/attachments.md` — done.

## Related

- Parent: #404.  Uses the listing helper from #404a.
- #391 — introduced unpacking phone uploads.
