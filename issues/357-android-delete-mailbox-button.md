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

Not started.
