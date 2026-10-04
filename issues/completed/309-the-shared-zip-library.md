# #309 — Zips are packed and read by the shared zip library, not the zip programs

## Status

Completed 2026-09-30. The owner, asked whether rmail and rao-chat should
share one zip reader and packer (my-libs issue 801): *"yes please"*.
Numbered in phase 4 beside #311, whose defences it replaces with one
reader.

Every attachment test passes under rmail's own Lua 5.4.7:
- `test-received-links.sh`
- `test-unpacked-size.sh`
- `test-phone-upload-checks.sh`
- `test-chunk-rules.sh`
- `test-torn-pack.sh`
- `test-attachment-ids-and-consent.sh`
- `test-consent-form-name.sh`
- `test-stale-transfer-records.sh`
- `test-attachment-round-trip.sh`
- the new `test-zip-library.sh`

## Current Behavior

Built:

- `libs/zip-{compat,inflate,reader,writer}.lua` are a copy of my-libs/zip,
  made by the library's `install-into`. `libs/zip-library.version` records
  each file's hash and the library commit. The copy lets rmail work where
  my-libs does not exist. `scripts/test-zip-library.sh` fails if the copy
  differs from the library, and runs the library's 23 checks on the Lua
  rmail runs on.
- `upload.zip_reader` and `upload.zip_writer` hold the library. The main
  chunk is at the 200-local ceiling.
- **Packing**: `compress_attachment` calls `zip_writer.pack`.
  - The packed path is followed once if it is a link. Links inside a
    folder are stored as links; the zip program used to follow them.
  - A change while packing is caught to the fraction of a second, as
    #311d's fingerprint was.
  - The 4th return value is the exact unpacked size. The declared
    `expected_size` stays `du -sb`: files are now stored, not compressed,
    and older receivers hold the pieces to the declared size plus 10% and
    4 KiB; `du -sb`'s folder blocks cover the zip's per-file headers.
  - **A regression, until compression exists** (rao-chat issue 217):
    attachments travel uncompressed, so text is about three times larger
    on the wire than with the zip program.
- **Contact attachments**: `upload.unpack_received(zip, dir, limit)` calls
  `zip_reader.extract` with `exact = false` and the #310 limit.
  - A refusal maps to `refuse_transfer` with the reader's reason.
    `unpacks-larger` keeps the old name, `oversize-unpacked`.
  - A failure of the disk, not the zip, still answers 500 and keeps the
    chunks.
  - A link whose own name holds a line break is now refused before
    anything is made (`bad-name`). Before, only the search after unzip
    caught it (`link-in-archive`).
- **Phone uploads**: `zip_reader.list`, then exactly one regular file.
  - Its claimed size must fit the free disk space, which is new: `unzip -p`
    had no bound.
  - It is extracted with the meter held to that claim, exactly, and moved
    to where `unzip -p` used to write it.
- Start-up no longer requires `zip` or `unzip`. `tools.zip` and
  `tools.unzip` are gone. `install.sh` still builds them, since the tests
  use them.
- Removed: `upload.list_entries` (zipinfo), `upload.unzip_pattern`,
  `upload.link_note` (the library writes the same note, word for word),
  `upload.measure_unpacked` (`unzip -p | head -c`).
- Tests changed:
  - `test-torn-pack.sh`'s stand-in is now `find`, which writes to the file
    after the packer's listing; the old stand-in was `zip`.
  - `test-phone-upload-checks.sh` damages byte 80, inside the compressed
    stream, and expects `refused damaged`. At byte 200 it had landed in
    the table of contents.
  - `test-received-links.sh` expects `bad-name` for the hidden link name.
- Docs: `README.md` (dependencies) and `docs/.templates/attachments.md`.

### Before this issue

- **Packing**: `compress_attachment` runs `zip -r` (a folder, from its
  parent) or `zip -j` (a file), following links. The declared size is
  `du -sb` of the source, which counts folder blocks, so it is not exact.
- **Contact attachments**: the joined zip is checked by `zipinfo` for link
  entries. It is measured by `unzip -p | head -c` against the declared size
  plus 10% and 4 KiB. It is then extracted by `unzip -x <links>` into a
  private folder, and links become notes. Any link left behind refuses the
  transfer (#311a, #310).
- **Phone uploads**: `upload.list_entries` requires exactly one regular
  file, then `unzip -p` writes it out and its exit status is read (#311c).
  No size bound applies.
- `zip` and `unzip` are required at start-up (#606).

## Intended Behavior

The shared library, `my-libs/zip` (linked into `libs/`), does all of it.
It runs on Lua 5.4 and on LuaJIT.

- **Contact attachments**: `zip-reader.extract` into the private folder.
  - The budget is rmail's existing limit (the declared size plus 10% and
    4 KiB), with `exact = false`. Senders running older rmail declare
    `du -sb` sizes, so rmail's protocol does not change here.
  - The reader checks the whole structure first:
    - names that climb out, and absolute names;
    - overlapping entries (a bomb that `unzip -p | head -c` would also
      count, but only by unpacking it);
    - devices;
    - encryption and ZIP64;
    - damaged data.
  - It then meters each entry before its bytes exist.
  - Links become the same notes as #311a's, with the owner's wording.
  - A refusal removes everything made and cancels the transfer like
    `oversize`, with the reader's one-word reason.
- **Phone uploads**: the reader lists the zip. Exactly one entry, a
  regular file, is required. Its claimed size must fit the free space on
  the disk, and it is extracted with the meter held to that claim.
- **Packing**: `zip-writer.pack` into the pending folder. The declared size
  is the writer's exact count.
  - It follows the attached path once if that path is a link. Links below
    it are stored as links, which receivers turn into notes. Before this,
    rmail's `zip` followed every link.
- `zip` and `unzip` are no longer needed to run rmail. The tests still use
  them, to prove agreement with the outside world.

## Suggested Implementation Steps

1. Link `libs/zip-*.lua` to my-libs. Load the reader and writer into the
   `upload` table (the main chunk is at Lua's 200-local ceiling).
2. Contact attachments: replace the `zipinfo` check, the size count and
   `unzip` with `extract`; map refusals to `upload.refuse_transfer`.
3. Phone uploads: replace `upload.list_entries` and `unzip -p`.
4. Packing: replace `zip` in `compress_attachment`, and the size taken by
   `du -sb`.
5. Start-up: drop the `zip`/`unzip` requirement. #606's detection stays
   in `install.sh` only for the tests.
6. Tests: every attachment test (`test-received-links.sh`,
   `test-unpacked-size.sh`, `test-phone-upload-checks.sh`,
   `test-chunk-rules.sh`, `test-attachment-round-trip.sh`,
   `test-torn-pack.sh`, `test-attachment-ids-and-consent.sh`,
   `test-consent-form-name.sh`, `test-stale-transfer-records.sh`) passes,
   under lua5.4.
