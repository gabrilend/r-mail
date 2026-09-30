# #404b — Every chunk carries its checksums, and the chunk count is fixed per transfer

## Status

Completed 2026-09-29.  Sub-issue of #404.  Covered by
`scripts/test-chunk-rules.sh` (all cases pass; against the code before
this change, 16 of its cases fail — among them a claim of a million
pieces answered with a million-entry "still missing" list).  An honest
two-daemon transfer in three pieces is covered by
`scripts/test-attachment-round-trip.sh`, which passes.

## Current Behavior

A contact's attachment arrives as numbered pieces (chunks) of one zip.
Each chunk request (`attachment_chunk`) carries:

| field | type | meaning |
|---|---|---|
| `attachment_id` | string | which transfer (the consent record's key) |
| `chunk_index` | number | which piece, counting from 0 |
| `total_chunks` | number | how many pieces the zip was cut into |
| `data` | string, base64 | the piece's bytes |
| `chunk_checksum` | string, 64 hex | SHA-256 of this piece |
| `total_checksum` | string, 64 hex | SHA-256 of the whole zip |

`handle_attachment_chunk` checks every claim before using it:

1. **Fields.**  `chunk_index` and `total_chunks` must be whole numbers
   (`upload.whole_number`: no fraction, not negative, below 2^53), with
   `0 ≤ chunk_index < total_chunks`; both checksums must be 64 hex digits
   (`upload.is_sha256`); the piece may not be empty.  Otherwise 400 with
   the reason.
2. **The piece's own checksum.**  A mismatch drops the piece; the answer
   lists what is still owed (`upload.missing_chunks`), or `[0]` when
   nothing is pinned yet.
3. **The shape is pinned at chunk 0.**  The consent record
   (`consent-pending.json`) keeps three fields:

   | field | type | meaning |
   |---|---|---|
   | `total_chunks` | number | the pinned count |
   | `total_checksum` | string | the pinned whole-zip SHA-256 |
   | `chunk_length` | number | the length of chunk 0 = every piece but the last |

   - Chunk 0 with no pin, or with a count or checksum that differs from
     the pin (the sender packed the file again after losing its zip):
     every piece on disk is discarded, the byte count (`bytes_received`)
     goes back to 0, and the new shape is pinned.  Refused at this point:
     a shape that cannot fit the declared size, `(total_chunks − 1) ×
     chunk_length` over the #327 limit — cancelled as `oversize`.  A count
     over `upload.MAX_CHUNKS` (100,000, shared with phone uploads) is
     refused with 400 among the field checks.
   - Any other chunk that does not match the pin (or arrives before any
     pin) is not stored; the answer is `missing = [0]`, which makes the
     sender send chunk 0 next.  An honest sender always sends chunk 0
     first — after consent and after re-packing — so it never meets this.
4. **Length.**  Every piece but the last must be exactly `chunk_length`;
   the last must be at most that.  Otherwise 400.
5. **Size.**  The packed running total against the #327 limit, as before;
   a resent piece only adds its difference.
6. **Owed pieces, a batch at a time.**  The consent record also keeps
   `pieces_held` (number: pieces on disk) and `low_water` (number: every
   piece below it is on disk), both reset to 0 at pinning and at a
   whole-zip mismatch.  The answer lists at most `upload.MISSING_ANSWER`
   (64) owed piece numbers, looking from `low_water`, and carries `held`.
   The transfer is complete only when the look finds nothing owed; the
   held count only feeds the progress shown, so a crash between writing a
   piece and saving the count cannot stall a transfer.  A transfer pinned
   before these fields existed counts its pieces on disk once
   (`upload.count_held`).  The sender (`send_next_chunks`) sends a batch,
   then the batch named by the last answer, within one cycle, bounded by
   `ceil(total / 64) + 2` passes.  It shows `held` in the progress file,
   or, for a receiver from before the batches, the count not listed.
7. **Whole zip.**  When all pieces are in, the assembled zip must match
   the pinned `total_checksum`.  A mismatch discards every piece, resets
   the byte count, and asks for all of them again (no single piece can
   be blamed: each matched its own checksum when it arrived).

### Before this issue (the problems it solved)

- A chunk without `chunk_checksum` skipped the piece check; one without
  `total_checksum` skipped the whole-zip check.
- `total_chunks` was believed from each chunk on its own; two chunks could
  disagree, and a claim of a billion pieces made the receiver look for a
  billion files and answer with a billion-entry list.
- `chunk_index` came from `tonumber`, so pieces numbered -3 or 2.5 were
  written to disk under those names.
- A "lazy" byte count summed whatever pieces were on disk the first time a
  transfer was seen; it is replaced by the reset at pinning.
- The whole-zip mismatch branch held a "re-verify each piece" step that
  did nothing; removed.

### Decisions

- **No smallest piece; a largest count instead.**  A 4096-byte floor was
  built first, and then taken out the same day.  The owner (2026-09-29):
  *"we were thinking about sending messages, which often are below 1kb,
  as attachments every single time. We need to find a way to dismantle
  the floor. I think option 3. is our best option for now."*  (Option 3:
  no floor, cap the count, as phone uploads already did at 100,000.)  The
  floor had only touched multi-piece transfers, since a one-piece message
  was always its own last piece.  Without it, the danger of tiny pieces
  was the receiver's work per piece: a look on disk for every piece, and
  an answer listing every owed piece.  The count cap bounds the total;
  the 64-piece answer batch and the low-water mark bound the work per
  piece.  At the 5 MiB default the cap allows about 500 GB per transfer;
  at 1 KiB pieces, about 100 MB.  Left as is: a contact who has been given
  consent can hold every piece but the first, and make each look walk
  the held pieces, up to 100,000 file checks (about a tenth of a second)
  per answer.
- A mismatching later piece gets "send chunk 0" rather than an error, so
  a sender that re-packed, or a transfer that was in flight when this
  change was installed, recovers on its own.

## Intended Behavior

No claim in a chunk is used before it is checked; checksums are
required; the count, whole checksum and piece length are fixed for a
transfer and re-fixed only by a new chunk 0.  (Built as above.)

## Suggested Implementation Steps

1. `upload.whole_number`, `upload.is_sha256`, `upload.missing_chunks`,
   `upload.count_held`, `upload.MAX_CHUNKS`, `upload.MISSING_ANSWER` in
   the `upload` table (the main chunk is at Lua's 200-local ceiling).
2. `handle_attachment_chunk`: field checks; piece checksum; pinning at
   chunk 0; "send chunk 0" for a mismatching later piece; length rule;
   size limit; whole-zip check against the pin.
3. Test `scripts/test-chunk-rules.sh` (stand-in contact,
   `scripts/lib/fake-contact.lua`; shared set-up,
   `scripts/lib/test-receiver.sh`).  Control test
   `scripts/test-attachment-round-trip.sh`: two real daemons, a 40 KB
   file in 16 KiB pieces, consent given by deleting "deny", the file
   arrives byte for byte.  (The receiver learns the sender's address only
   when it answers the form: two daemons on one machine dialling each
   other at the same moment wait on each other, a separate problem —
   #387.)
4. `docs/.templates/attachments.md`: a bullet under "What a received
   attachment is not allowed to do".

## Related

- Parent: #404.  Followed by #404e, which changes the same handler.
- #327 — the packed-size limit used to bound the count.
- #387 — the blocking sync cycle the round-trip test steps around.
