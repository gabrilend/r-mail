# #805 — What the Android app shows, screen by screen

## Status

Completed — a blueprint written 2026-10-04 (#621) for what was built
before issue files described it.  The issues after it in phase 8 each
refine one of these screens.

## Current Behavior

The app (`ui/MainActivity.kt`, one `MainViewModel` holding the state)
moves between screens by name:

| screen | what it is |
|---|---|
| **mailbox list** (`MailboxListScreen`) | every home mailbox the app holds; add one, open one, delete one (#815) |
| **setup** (`SetupScreen`) | a new mailbox: addresses, port, token; tests the connection before saving (`AddressListEditor` files each address as public or local) |
| **main** (`InboxScreen`) | the mailbox, with a bottom bar of four panels: **Contacts**, **Inbox**, **Outbox**, **Files**; the title opens the mailbox list (#817) |
| **read** (`ReadScreen`) | one message, in a monospace column fitted to the screen (80 characters by default, +/- to change, #809); Reply and Forward start a draft (#816); an outbox message can be edited and sent again as an update (#812) |
| **compose** (the compose panel) | a new message: recipients picked from contacts, the body, attachments from the attachment picker (`AttachmentSourcePicker`, #820); a name already in the outbox is refused (#814); the cursor is kept in view while typing (#806) |
| **files** (`AttachmentsScreen` / the Files panel) | received attachments: thumbnails, open, save to the device's shared folders (#821), delete |
| **contacts** (`ContactsScreen` / the panel) | the contacts, editable; saved through the home daemon (#504) |
| **settings** (`SettingsScreen` / the panel) | per mailbox: addresses, background sync, notifications; for the app: colours |

Consent forms appear in the inbox like messages and can be answered
there.  Messages being sent show a progress bar (#813); a failed sync
keeps its error visible until the next one succeeds (#808).  Swiping a
message away to delete it is off unless turned on (#819).

## Intended Behavior

As above; #825 collects ideas beyond it.

## Suggested Implementation Steps

1. `ui/MainActivity.kt` (the navigation), `ui/MainViewModel.kt`,
   `ui/screens/*.kt`, `ui/theme/Theme.kt`.
2. Build and install: `scripts/compile-android.sh`; the guide is
   `docs/.templates/android-instructions.md`.

## Related documents

- `#825`, `#814`, `#806`, `#808`, `#809`, `#812`, `#813`, `#815`,
  `#816`, `#817`, `#819`, `#820`, `#821`, `#504`
