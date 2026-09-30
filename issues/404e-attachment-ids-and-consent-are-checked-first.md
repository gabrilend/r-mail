# #404e — Attachment ids are checked before they name a folder, and no chunk is taken before consent

## Status

Open, 2026-09-29.  Sub-issue of #404.  Found while doing #404a–#404d;
not in the list the owner approved, but the same kind of gap in the same
handler (a contact's claim used without checking).  Flagged to the owner
in the report for that reason.

## Current Behavior

- `handle_attachment_request` stores the sender's `attachment_id` as the
  key of the consent record without looking at it.  The chunk handler
  then builds `<pending>/.pending/<attachment_id>` from it and, on
  cancellation or oversize, runs `rm -rf` on that path.  An id of
  `../../home/you` makes that `rm -rf /tmp/.pending/../../home/you`.
- `handle_attachment_chunk` accepts chunks for any consent record not
  being cancelled — including one still waiting for the owner's answer
  (`pending`) or already declined (`declined`).  A contact can therefore
  send the whole attachment before the owner says yes, and it is filed.

## Intended Behavior

- An `attachment_id` must look like the ids rmail makes (`uuid()`: hex
  digits and dashes, 8 to 64 characters); a request or chunk with any
  other id is refused with 400.
- Chunks are taken only when the owner has said yes: consent record
  status `accepted` (answer recorded, not yet delivered to the sender) or
  `receiving` (answer delivered).  Otherwise the answer is 403
  "no consent for this attachment" and nothing is written.

## Suggested Implementation Steps

1. `upload.valid_attachment_id(id)`.
2. `handle_attachment_request` and `handle_attachment_chunk`: check it
   first.
3. `handle_attachment_chunk`: the consent-status check.
4. Test `scripts/test-attachment-ids-and-consent.sh`: a request with id
   `../../x` → 400, and a marker folder outside the pending folder
   survives; a chunk before consent → 403 and no piece on disk; the same
   chunk after consent → taken.

## Related

- Parent: #404.  Changes the same handler as #404b, after it.
