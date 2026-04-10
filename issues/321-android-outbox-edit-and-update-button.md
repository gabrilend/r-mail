# #321 — Redesign outbox message editing and update button on Android

## Problem

The update button behavior in the outbox view is unclear. Editing an outbox
message should be more intuitive.

## Desired behavior

### Update button
- Should only show zipping/transfer progress. Disappears if there's nothing
  in progress.

### Editing outbox messages
- Tapping a message opens it for reading. Tapping where you want your cursor
  seamlessly switches to the compose screen with all previous details filled
  in (to, attachments, subject) — all editable.
- The "send" button becomes "save".
- The back button (both top-left and Android back) asks "save changes?" —
  "no" discards changes.
- Saving is the same as the top-right button.

### Recipient changes
- Removing a `to:` line marks that recipient for deletion on their side.
- Adding a new `to:` line sends as a new message to the new recipient,
  and as an update to existing recipients.

## Source

From `rmail-update-vutton`.
