# #404e — Attachment ids are checked before they name a folder, and no chunk is taken before consent

## Status

Completed 2026-09-29.  Sub-issue of #404.  Found while doing
#404a–#404d; not in the list the owner approved, but the same kind of gap
in the same handler (a contact's claim used without checking), and the
first half of it let a contact delete folders outside rmail's own.
Flagged to the owner for that reason.  Covered by
`scripts/test-attachment-ids-and-consent.sh` (all cases pass; against the
code before this change, 4 of its cases fail — including the test's
stand-in folder outside the pending area being removed by a contact).

## Current Behavior

- **Ids.**  A contact chooses the `attachment_id` of each attachment it
  offers.  The receiver keys the consent record by it and names the
  transfer's folder after it, `<pending>/.pending/<attachment_id>`, which
  is removed with `rm -rf` on cancellation, oversize or completion.
  `upload.valid_attachment_id` accepts only the shape `uuid()` makes: a
  string of 8 to 64 hex digits and dashes.  `handle_attachment_request`
  and `handle_attachment_chunk` check it first and answer 400 otherwise.
- **Consent.**  `handle_attachment_chunk` takes a piece only when the
  consent record's status is `accepted` (the owner's yes is recorded and
  on its way to the sender) or `receiving` (it arrived).  Any other status
  — `pending` (unanswered) or `declined` — answers 403 "no consent for
  this attachment", logs it, and writes nothing.  An honest sender never
  meets this: it sends pieces only after the yes reaches it.

### Before this issue (the problems it solved)

- The id was used as given.  An id of `../../home/you` made the transfer's
  folder `<pending>/.pending/../../home/you`, and an oversize piece (or a
  cancellation) then ran `rm -rf` on it.  With the default pending folder
  `/tmp`, that is `/home/you`.
- Pieces were taken for any record not being cancelled, including one
  still waiting for the owner's answer: a contact could send the whole
  attachment unasked, and it was filed.

## Intended Behavior

A contact cannot name a folder outside the pending area, and cannot
deliver an attachment the owner has not accepted.  (Built as above.)

## Suggested Implementation Steps

1. `upload.valid_attachment_id` (next to `upload.fingerprint`, above
   `compress_attachment`).
2. `handle_attachment_request`, `handle_attachment_chunk`: check the id
   first.
3. `handle_attachment_chunk`: the consent-status check after the
   cancellation check.
4. Test `scripts/test-attachment-ids-and-consent.sh`.
5. `docs/.templates/attachments.md`: a bullet under "What a received
   attachment is not allowed to do".

## Related

- Parent: #404.  Follows #404b in the same handler.
