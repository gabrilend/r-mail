# #310 — Reject transfers that are bigger than the sender said, packed or unpacked

## Status

Completed (second time) 2026-09-29.  The first part — count the packed
bytes as they arrive — was built earlier in 2026.  Reopened on
2026-09-29 for the unpacked size, as part of #311 (received attachments
are untrusted input).  Covered by `scripts/test-unpacked-size.sh` (all
cases pass; against the code before this change, 7 of its cases fail,
including a 1 MiB zip bomb filed from 1201 packed bytes).

## Current Behavior

The `Expected size` in an attachment request is declared by the sender:
the sending daemon measures the original file or folder with `du -sb`
(bytes of content, plus the folders themselves for a folder) and puts that
number in the request.  The receiver shows it on the consent form.

One limit, from `upload.size_limit(expected_size)`:
`expected_size × 1.1 + 4096` bytes — 10% for zip's own bookkeeping on
already-compressed files (jpg, mp3), and 4 KiB so tiny files are not
refused over a few bytes of headers.  It is applied twice:

1. **Packed bytes, as they arrive.**  `handle_attachment_chunk` keeps a
   running total of chunk bytes (`bytes_received` in the consent record;
   a resent chunk only adds the difference) and cancels the transfer when
   it would pass the limit, `rejection_reason = "oversize"`.
2. **Unpacked bytes, before extraction.**  After the whole zip's checksum
   matches and before anything is written, `upload.measure_unpacked`
   really decompresses every entry into a counter:
   `unzip -p <zip> | head -c <limit+1> | wc -c`.  `head` stops one byte
   past the limit and closes the pipe, which stops `unzip`, so a zip bomb
   costs a fraction of a second and no disk.  More than the limit cancels
   the transfer, `rejection_reason = "oversize-unpacked"`, with a log line
   giving the declared size and the limit.  The sizes a zip's table of
   contents claims (`unzip -l`) are not used: the sender writes them.

Cancelling (`upload.refuse_transfer`) removes the pending folder, removes
the consent form, and marks the record `cancel_pending`, which
`send_attachment_cancellations` turns into a notice to the sender.

The declared size must be real: `handle_attachment_request` refuses a
request whose `expected_size` is missing, negative or not a whole number
with 400.  A declared 0 is a real size, limit 4096 bytes.

### Before this issue (the problems it solved)

- Nothing was counted: a sender could declare a small file and stream any
  amount (first part, 2026).
- Only packed bytes were counted, so a zip of a few kilobytes could unpack
  into gigabytes (the zip bomb).
- A declared size of 0 switched the packed check off, and a missing size
  was read as 0 — so a sender declaring nothing had no limit at all.

## Intended Behavior

No transfer takes more than its declared size allows, packed or
unpacked; a sender cannot switch the limit off.  (Built as above.)

## Suggested Implementation Steps

1. `handle_attachment_request`: require a whole-number `expected_size`.
2. `handle_attachment_chunk`: packed running total against
   `upload.size_limit`, whatever the declared size.
3. `upload.size_limit`, `upload.measure_unpacked` in the `upload` table
   (the main chunk is at Lua's 200-local ceiling).
4. `handle_attachment_chunk`, after the whole-zip checksum: measure,
   refuse over the limit, then unpack (#311a).
5. Test `scripts/test-unpacked-size.sh` (shared set-up in
   `scripts/lib/test-receiver.sh`, stand-in contact in
   `scripts/lib/fake-contact.lua`): zip bomb refused and nothing filed;
   honest file of the declared size arrives whole; 5000 bytes against a
   declared 0 refused; a request with no size or 10.5 bytes refused.
6. `docs/.templates/attachments.md`: the size is enforced both ways.

## Related

- #311 — received attachments are untrusted input (parent of this round).
- #311a — the unpacking step this measurement sits in front of.
- #307 — the attachment pipeline audit that introduced extracting into a
  private folder first.

## Source

From an inline comment in `docs/attachments.md` (first part); a security
read of the receive path on 2026-09-29 (second part).
