# #357 — Add delete-mailbox button in Android settings

## Problem

There's no way to remove a mailbox from the Android app. Once added,
it stays in the mailbox list forever. Users who set up a test mailbox,
switched home servers, or want to cleanly disconnect from a relationship
have to reinstall the app.

## Desired behavior

Add a **Delete Mailbox** button to the Settings panel. Tapping it
shows a confirmation dialog that:

1. Warns the deletion is permanent: "this will permanently sever your
   connection to your mailbox."
2. Reassures the user their files on the home server are safe — **but
   only if nothing is pending sync**. If there are unsynced files
   (outbox messages not yet delivered, attachments still chunking,
   contacts edits not yet pushed), list them:

   > "Your mailbox files should be safe on the home server, unless
   > they haven't synced yet. Here are the files that haven't synced
   > yet:
   >
   >   outbox/my-note
   >   attachments/big-video.mp4  (uploading, 3/17 chunks)
   >   contacts  (edited, not saved)"

3. If the mailbox is fully in sync, the message becomes: "Your mailbox
   files are safe on the home server."
4. Confirm / Cancel buttons. On confirm, the mailbox is removed from
   `MailboxRegistry` and the local mailbox directory (`MailStore`) is
   deleted.

## Implementation notes

- "Unsynced files" = anything in `outbox/` the server doesn't have yet
  + any chunk upload in progress (`chunks-outgoing.json` on the phone
  side) + modified contacts that haven't been saved.
- The confirmation message builder should query these state files
  before showing the dialog; if the sync state isn't loadable
  (offline), assume "may have unsynced files" and list the local
  outbox contents.
- Cancel leaves everything untouched. No "Are you sure?" chain.
- After deletion, navigate back to the mailbox list.

## Source

From `issues/android-123`.

## Status

Shipped.

- New `Danger zone` section at the bottom of the Settings panel
  with an outlined red **Delete mailbox** button.
- Tapping it opens an `AlertDialog` explaining that severing the
  connection does not touch the home server, then lists anything
  on the device that hasn't been round-tripped to the server yet.
  Today that's the local outbox contents (conservative: every
  local outbox file is reported, since the phone's sync-state
  doesn't yet track per-file delivery confirmation — better to
  over-warn than silently lose).
- `MainViewModel.unsyncedSummary()` produces the list;
  `MainViewModel.removeMailbox(id)` deselects if active, removes
  the config from `MailboxRegistry`, and the registry's own
  `remove()` deletes the on-device mailbox directory.
- On confirm, the dialog closes, the mailbox is removed, and the
  Inbox screen calls `onBack()` to navigate to the mailbox list.
- Cancel closes the dialog without touching anything.
