# #404b — Every chunk carries its checksums, and the chunk count is fixed per transfer

## Status

Open, 2026-09-29.  Sub-issue of #404.

## Current Behavior

A contact's attachment arrives as numbered chunks of one zip.  Each
chunk request (`attachment_chunk`) carries:

| field | type | meaning |
|---|---|---|
| `attachment_id` | string | which transfer |
| `chunk_index` | number | which piece, counting from 0 |
| `total_chunks` | number | how many pieces the zip was cut into |
| `data` | string, base64 | the piece's bytes |
| `chunk_checksum` | string, 64 hex | SHA-256 of this piece |
| `total_checksum` | string, 64 hex | SHA-256 of the whole zip |

`handle_attachment_chunk`:

- skips the piece check when `chunk_checksum` is absent, and the
  whole-zip check when `total_checksum` is absent;
- believes `total_chunks` from each chunk on its own, so two chunks can
  disagree, and a chunk claiming a billion pieces makes the daemon loop a
  billion times looking for them;
- takes `chunk_index` from `tonumber`, so `-3`, `2.5` or `1e9` are
  written as `chunk--3`, `chunk-2.5`, … and never used.

The sender may legitimately change `total_chunks` and `total_checksum`
mid-transfer: when its zip was wiped (a reboot clears `/tmp`) it packs
the file again and resends every chunk, starting at chunk 0
(`send_next_chunks`).

## Intended Behavior

- `chunk_checksum` and `total_checksum` are required, 64 hex characters;
  a chunk without them is refused with 400.
- `chunk_index` and `total_chunks` must be whole numbers,
  `0 ≤ chunk_index < total_chunks`; otherwise 400.
- **The transfer's shape is pinned at chunk 0.**  The consent record
  keeps `total_chunks`, `total_checksum` and `chunk_length` (the length
  of chunk 0; every chunk but the last is cut to the same length by the
  sender).  When chunk 0 arrives:
  - nothing pinned yet → pin, and discard any pieces already on disk;
  - pinned with the same count and checksum → an ordinary resend;
  - pinned with a different count or checksum → the sender packed the file
    again: discard all pieces, reset the byte count, pin the new shape.
- A later chunk with no pin, or with a count or checksum that differs
  from the pin, is not stored; the answer asks for chunk 0 (`missing =
  [0]`), which the sender sends next and which re-pins.
- Every chunk but the last must be exactly `chunk_length` long; the last
  must be between 1 and `chunk_length`.  Otherwise 400.
- The count is bounded when pinned: `(total_chunks − 1) × chunk_length`
  must not exceed the packed-size limit of #327; a shape that could never
  fit is refused as oversize.  A piece shorter than 4096 bytes that is not
  the last one is refused, so a sender cannot declare a vast number of
  one-byte pieces.
- On a whole-zip checksum mismatch every piece is discarded and all are
  asked for again (as now); the dead "per-chunk re-verify" branch that
  never did anything is removed.

## Suggested Implementation Steps

1. `handle_attachment_chunk`: validate the fields first (types, ranges,
   hex shape) and answer 400 with the reason.
2. Pinning as above, stored in the consent record (`consent-pending.json`
   entry fields `total_chunks`, `total_checksum`, `chunk_length`).
3. Replace the lazy "count bytes already on disk" start-up with a reset at
   pin time.
4. Clean the whole-zip mismatch branch.
5. Test `scripts/test-chunk-rules.sh` with the stand-in contact: no
   checksum → 400; no total checksum → 400; negative, fractional and
   out-of-range index → 400; a later chunk before chunk 0 → asked for 0;
   a chunk with a different count → asked for 0; a short middle chunk →
   400; a huge count → cancelled as oversize; an honest transfer sent out
   of order after chunk 0 → arrives.

## Related

- Parent: #404.  Followed by #404e, which changes the same handler.
- #327 — the packed-size limit used to bound the count.
