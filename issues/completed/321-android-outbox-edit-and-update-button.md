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

## Status

Core editing loop shipped; tap-anywhere gesture and dedicated
update-progress indicator deferred.

### Shipped

- **"Update" button removed** from the outbox ReadScreen. It used
  to retrigger the sync — same thing the top-bar refresh icon
  already does — and the spec wanted it to show transfer progress
  instead. Gone for now; a proper progress indicator can be added
  separately.
- **Edit button** (pencil icon) added to the outbox ReadScreen
  top-bar actions. Tapping it parses the outbox file's headers
  (`to:` and `attach:`) and body, queues a `PendingDraft` tagged
  with `editingOutboxFilename`, and pops back to the InboxScreen
  which switches to the Write panel pre-filled.
- **Send → Save in edit mode.** When `editingOutboxFilename != null`
  the top-right action shows a checkmark icon labelled "Save". On
  tap it overwrites the existing outbox file (no new filename
  generation, no duplicate-subject guard — the file already
  existed). The send-progress animation is also suppressed for
  edits — the daemon's living-messages mechanism handles the
  delivery diff invisibly.
- **`attach:` line preservation.** Existing attach paths from the
  outbox file ride through the edit as-is (stored in
  `editingAttachLines`, re-emitted on save). Users don't see them
  in the composer UI in this pass — they're invisible-but-preserved.
- **Dirty-back confirmation.** A `BackHandler` and a
  hooked-into-title-tap path open a "Save changes?" dialog when
  the user tries to leave with unsaved edits. **Discard** clears
  the edit state and returns to Outbox; **Keep editing** dismisses
  the dialog. The Save action goes through the Save button itself.

### Deferred

- **"Tap anywhere on the message body to start editing at that
  cursor position"** gesture from the spec. Today's design uses an
  explicit Edit IconButton, which is more discoverable but less
  fluid than the spec's vision. Left for after on-device feedback
  on whether the explicit button is good enough.
- **Visible attach-line management** in edit mode. Currently
  preserved invisibly; ideally the user can see/remove existing
  attachments while editing.
- **Update progress indicator** at the position the old Update
  button occupied — show zipping / chunk progress when an
  attachment transfer for this message is in flight. Out of scope
  for this pass; the existing transfer-state plumbing has the
  data, just needs a visual.

### Recipient changes

The spec says removing/adding `to:` lines should propagate
correctly. The daemon's `sync_outbox` already handles this via
the existing living-messages diff — when an outbox file's
recipient set changes, the daemon queues `notify_removal` for
removed recipients, `deliver` for new ones, and `update` for
existing ones whose body changed. **No client-side work needed**;
saving the edited file is enough.
