# #378 — Android: export mailbox to a user-chosen location

## Problem

On Android the mailbox lives in `context.filesDir`
(`data/MailStore.kt:21-25`):

```
/data/data/com.rmail.app/files/mailbox-<id>/{inbox,outbox,attachments,contacts}
```

That is app-private storage.  It is invisible to every file browser, it
cannot be reached without root or `adb run-as` on a debug build, and the
only interface to a user's own messages is our application.  If the app
is uninstalled, or simply if the user wants to keep a note somewhere
else, there is no supported way to get a text file off the device.

That's wrong on principle — these are plain text files the user wrote,
and they should be able to take them, read them in another app, or back
them up without our system being in the loop.

## Decision: export, not relocation

The obvious fix is to move the store to shared storage
(`Documents/r-mail/…` via MediaStore, or an SAF tree).  **We are
deliberately not doing that.**  Mail in shared storage is readable by
any app the user grants storage access to, it survives uninstall, and
the media scanner will index the `.txt` files.  For a project whose wire
protocol is AES-GCM and which has open issues on traffic padding (#366)
and decoy traffic (#314), plaintext mail sitting in `/sdcard/Documents`
is a meaningful step down in posture.

So: **storage stays private; export becomes an explicit, user-initiated
action.**  The user chooses what leaves the sandbox and when.

## Requirements

From the 2026-09-21 discussion:

1. **Per-mailbox.**  Export acts on one mailbox, not the whole app.
2. **Individual message selection.**  The user picks *which* files go —
   not an all-or-nothing dump.
3. **Two entry points:**
   - A **"Export mailbox"** button in mailbox settings, near the
     existing **"Delete mailbox"** button.
   - An entry in the **mailbox picker's three-dot dialog**, placed on the
     **left side, opposite the "Close" button**.
4. Exported files land somewhere the user chooses and can reach with a
   file browser or hand to another app.

## Where the entry points go

**Settings button.**  "Delete mailbox" is at `ui/screens/InboxScreen.kt:1321-1331`
— an `OutlinedButton` in error colours under a `"Danger zone"` heading
at the very bottom of the settings pane.  Export is *not* destructive,
so it should sit **above** the Danger zone divider, not inside it —
adjacent as requested, but visually separated from the red section.

**Picker dialog.**  The three-dot on each row opens an `AlertDialog` at
`ui/screens/MailboxListScreen.kt:75-91`, currently with only a
`confirmButton` holding "Close".  Adding `dismissButton = { TextButton(…)
{ Text("Export") } }` puts it on the left, opposite Close, which is
exactly the requested layout — Material places `dismissButton` to the
left of `confirmButton`.

## Proposed design

### Selection UI

A dedicated screen (not a dialog — the list can be long):

- Messages grouped by folder (Inbox / Outbox), each row a checkbox with
  subject/filename, sender or recipient, and date.
- Per-group and global **select all / none**.
- Running count + total size of the selection.
- Attachments: either a third group, or an "include attachments for
  selected messages" toggle.  **Undecided.**

`MainViewModel.unsyncedSummary()` (`ui/MainViewModel.kt`, used by the
delete-confirmation dialog) already enumerates mailbox contents for a
similar purpose and is worth reusing or generalising rather than writing
a second enumerator.

### Destination

SAF, so no storage permission is needed and the user picks the location:

- `ACTION_CREATE_DOCUMENT` with a `.zip` mime type for a single-archive
  export, **or**
- `ACTION_OPEN_DOCUMENT_TREE` to pick a folder and write loose `.txt`
  files into it.

Loose files are friendlier for "read this in another app"; a zip is
friendlier for "back this up".  Probably offer both, with loose-files as
the default for small selections and zip above some threshold —
**undecided, see open questions.**

Preserve message mtimes on export where SAF allows it; the daemon went
to some trouble to keep authoring time meaningful (commit `d491ee8`,
#374) and an export that stamps everything with "now" throws that away.

### Share-to-another-app

Separately from file export, a `FileProvider` would let a single message
go straight out through `ACTION_SEND` to any app.  That is arguably the
more common "pass it to another app" case and is small on its own —
could ship first, or as part of this.

## Open questions

- Zip vs loose files vs both — and if both, where does the user choose?
- Do exported messages keep the raw on-disk format (`to:` header and
  all), or get rendered into something more portable?  Raw round-trips
  back into r-mail; rendered reads better everywhere else.
- Filename collisions in the destination folder — overwrite, skip, or
  suffix?  Note the daemon already has a dedupe-suffix convention
  (`-22fffd`, `-9bd652`) worth matching.
- Should export be available while a sync is in flight, or does it need
  to quiesce first to avoid exporting a half-written file?
- Does the exported set need a manifest (which mailbox, when exported,
  which files) for a future **import**?  Import is out of scope here but
  a manifest is cheap insurance if we ever want it.
- Attachments can be large — does the selection screen need a size
  guard or progress UI for multi-hundred-MB exports?
- Should the picker-dialog "Export" entry jump straight to the selection
  screen for that mailbox, or is it a shortcut for "export everything"?
  The requirement says selection must be possible; it doesn't say the
  shortcut can't exist.

## Origin

Filed 2026-09-21.  Prompted by mail being unreachable outside the app
during an unrelated investigation — recovering 41 stranded outbox notes
required `adb exec-out run-as com.rmail.app tar`, which is not a thing a
user can be asked to do.  The privacy tradeoff was discussed explicitly
and export-over-relocation was chosen deliberately.

## Status

Open.
