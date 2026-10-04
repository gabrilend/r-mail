# #820 — Android: attachment "+" bottom sheet with a Photo Picker route

## Status

Completed 2026-09-23.  Implemented 2026-09-22 (commits "Gallery/File
picker, received attachments stop overwriting, F-Droid issue" and "Android
picker: Camera source and a remembered app per source"), differently from
the bottom-sheet sketch this issue began with -- the owner asked for a
different design (see Current Behavior).

Verified by **reading the Kotlin source only**.  No APK was built or run
for this check (there is no build output on this machine), and there is no
automated Android test for the picker.  Whether the installed app on the
phone already carries this code was not checked.

## Current Behavior

Every "pick a file" in the app goes through one dialog of our own,
`AttachmentSourcePicker.kt` (`rememberAttachmentSourcePicker(onPicked)`,
which returns a function that opens the dialog).  It is used by:

- the attach button in the compose screen (`ComposeScreen.kt`),
- the attach button in the compose view inside `InboxScreen.kt`,
- the Files tab's `+` and its Upload button (the same action on purpose:
  both copy the picked files into Files; the next sync uploads them).

The dialog is titled "Add from" and shows three equal square buttons in a
row, each a Material icon over a word, plus a hint line "Long press to
change default app" and a Cancel text button:

| button  | intent sent                                                                 | returns            |
|---------|-----------------------------------------------------------------------------|--------------------|
| Gallery | `ACTION_PICK` on MediaStore images, `EXTRA_MIME_TYPES` image/* + video/*, `EXTRA_ALLOW_MULTIPLE` | one or many URIs |
| Camera  | `ACTION_IMAGE_CAPTURE`, output into a FileProvider file under `files/camera/IMG_<date>.jpg` | the file we supplied |
| File    | `ACTION_GET_CONTENT`, `*/*`, `CATEGORY_OPENABLE`, `EXTRA_ALLOW_MULTIPLE`    | one or many URIs   |

- **The first tap on a source** wraps its intent in `Intent.createChooser`,
  so Android asks *which* gallery / camera / file app to use.  The chooser
  reports the app picked through `EXTRA_CHOSEN_COMPONENT`, delivered to a
  broadcast receiver via a `PendingIntent`; the component name is stored in
  the `attachment_sources` shared preferences under the source's key.
- **Later taps** launch the remembered app directly.  **A long press**
  ignores the remembered app and shows the chooser again.  A remembered app
  that no longer resolves (uninstalled) is forgotten and the chooser comes
  back.
- **Newest first:** no intent can ask for a sort order.  Gallery apps open
  on their own timeline, and the system file picker opens on Recent when no
  starting folder is passed, so none is ever passed.
- **Camera** needs no CAMERA permission: the camera app takes the picture
  and writes it into our file; the write grant rides on `ClipData` so it
  survives the chooser.  The output URI and last source are kept in
  `rememberSaveable` so they survive the activity being recreated while the
  camera app is in front.  Photos older than a week in `files/camera/` are
  leftovers (a shot the user backed out of) and are deleted when the next
  camera file is made.  The FileProvider path `files-path "."` in
  `res/xml` already covers `files/camera/`.
- **Folder attach is unchanged:** a separate folder button next to the
  attach button launches `OpenDocumentTree` and walks the tree.
- Picked URIs flow into the same attachment list as before
  (`ComposeAttachmentEntry` / `AttachmentEntry` with display name and MIME
  type) and the same upload path.

## Intended Behavior

Attaching an image should open somewhere that shows the newest photos
first, with multi-select, instead of the Storage Access Framework document
picker, whose name-sorted list of opaque camera filenames is effectively
shuffled.  The user chooses the kind of source in rmail's own dialog and
the actual app in Android's, once, and is not asked again unless they want
to be.  The same picker serves every place in the app that picks a file.

### The original problem

The Compose attachment section offered two `IconButton`s — a folder
picker and a file picker (`ComposeScreen.kt:306-311` at the time):

```kotlin
IconButton(onClick = { dirPicker.launch(null) }) {
    Icon(Icons.Default.Folder, contentDescription = "Attach folder")
}
IconButton(onClick = { filePicker.launch(arrayOf("*/*")) }) {
    Icon(Icons.Default.Add, contentDescription = "Attach file")
}
```

Both routed through the Storage Access Framework document picker
(`OpenDocument` / `OpenDocumentTree`).  For **images** this is a poor
experience: SAF's DocumentsUI defaults to sorting by name, and Android
gallery images have random/opaque filenames (`20260528_153135.jpg`,
content-hashes, etc.), so the list is effectively shuffled.  The app
**cannot** fix this — SAF sort order is a system-controlled,
per-user-persistent DocumentsUI preference with no launch-time override
(the only hint available is `EXTRA_INITIAL_URI` for the starting
folder, not sort).

### The first proposal (not built)

The issue first proposed the **Android Photo Picker**
(`PickVisualMedia` / `PickMultipleVisualMedia`): it opens to the gallery,
is most-recent-first by default, supports multi-select natively, and
returns `content://` URIs that drop into the existing upload flow (minSdk
26; backported via Google Play services).  The two icon buttons would be
replaced by a single **"+"** control opening a `ModalBottomSheet` with
four rows:

1. **Directory** → `dirPicker.launch(null)` (existing `OpenDocumentTree`)
2. **Image** → new `PickMultipleVisualMedia` launcher
3. **File** → `filePicker.launch(arrayOf("*/*"))` (existing `OpenDocument`)
4. *(visual gap)*
5. **Cancel** → dismiss; rendered in red (`MaterialTheme.colorScheme.error`)

Rows were to be full-width pill-shaped buttons (`RoundedCornerShape(50)`)
with text and an emoji at each far edge, no Material vector icons:

```
📁   Directory        📁
🖼️   Image            🖼️
📄   File             📄

❌   Cancel           ❌     ← red
```

The Image row's callback was to mirror the existing single-file callback:

```kotlin
for (uri in uris) {
    val name = resolveDisplayName(context, uri) ?: uri.lastPathSegment ?: "attachment"
    val mime = try { context.contentResolver.getType(uri) } catch (_: Exception) { null }
    attachments.add(ComposeAttachmentEntry(uri, name, mime))
}
```

(That callback shape is what the built picker's `onPicked` handlers use.)
Everything downstream was to be unchanged: the same list and the same
`vm.uploadAttachmentsInBackground(filename, attachments.map { it.uri })`
call, which already ingests `content://` URIs — so this feature did **not**
depend on the `content://` fix noted in
[[315-loopback-attachments-via-chunk-system]], which is on the share-intent
/ older-client path.

### Why it was built differently (decided against)

The owner asked instead for an rmail dialog offering **Gallery** or
**File**, after which Android's own chooser asks *which* gallery or file
app to use.  So:

- **The Photo Picker route was not used**: it is not an app the user can
  choose between.
- **File uses `ACTION_GET_CONTENT`, not `OPEN_DOCUMENT`**: `OPEN_DOCUMENT`
  always goes to the system picker, so there would be no app to choose.
- **No SAF sort setting** — established as impossible.
- Later the same day a third source, **Camera**, was added, and the app
  chosen for each source became remembered, with long-press to change.

### Open questions from the sketch, and how they were settled

- *Max selection count for `PickMultipleVisualMedia`?* — Moot: the Photo
  Picker was not used, and neither `ACTION_PICK` nor `ACTION_GET_CONTENT`
  has a standard extra for a cap.  No cap exists.
- *Exact labels, emoji, same emoji on both edges?* — Superseded by the
  owner's dialog: words "Gallery", "Camera", "File" under Material icons,
  no emoji.
- *Should File also become multi-select?* — Yes; File sends
  `EXTRA_ALLOW_MULTIPLE`.
- *Row text alignment?* — Moot; the dialog uses three square buttons, not
  rows.
- *Does InboxScreen's attachment UI get the same sheet?* — Yes; every pick
  in the app uses the one dialog, including the Files tab.

## Suggested Implementation Steps

1. `clients/android/app/src/main/kotlin/com/rmail/app/ui/screens/AttachmentSourcePicker.kt`:
   - a `Source` enum (`GALLERY`, `CAMERA`, `FILE`) holding the preference
     key, the label, the Material icon and the chooser title;
   - `galleryIntent()`, `fileIntent()`, `cameraIntent(uri)` and
     `newCameraFile(context)` as in the table above (camera files under
     `filesDir/camera/`, served by the app's FileProvider, week-old files
     pruned);
   - `rememberAttachmentSourcePicker(onPicked: (List<Uri>) -> Unit)`: a
     `StartActivityForResult` launcher; `urisFrom(intent)` reads
     `clipData` first, then `data`; for Camera the result is the output
     URI we supplied;
   - a `BroadcastReceiver` (registered not-exported in a
     `DisposableEffect`) for the private action
     `com.rmail.app.ATTACH_SOURCE_CHOSEN`, storing
     `EXTRA_CHOSEN_COMPONENT` in the `attachment_sources` preferences;
   - `launch(source, ask)`: if not asked and a remembered component
     resolves, launch it directly; otherwise forget it and launch
     `Intent.createChooser(target, title, pendingIntent.intentSender)`;
   - the `AlertDialog` with three `SourceButton`s (`combinedClickable`:
     tap = remembered app, long press = ask again).
2. `ComposeScreen.kt`: replace the file-picker launcher with
   `rememberAttachmentSourcePicker`, adding each URI as a
   `ComposeAttachmentEntry`; keep the folder button on `OpenDocumentTree`.
3. `InboxScreen.kt`: one picker for attaching to the message being
   written (`pickAttachments`, adding `AttachmentEntry`s) and one for the
   Files tab `+` and Upload (`addToFiles`, calling
   `MainViewModel.addToFiles(uris)`).
4. Check by hand on a device: each source's first tap shows the chooser;
   the second tap goes straight to the chosen app; long press asks again;
   Gallery and File return several items; Camera returns the photo after
   an activity recreation; uninstalling the remembered app brings the
   chooser back.  Rebuild and install the APK
   (`scripts/compile-android.sh`) to reach the phone.

## Related

- [[315-loopback-attachments-via-chunk-system]] — the `content://` fix on
  the share-intent path (not needed by this picker).
- [[307-attachment-pipeline-audit]] — Files tab `+` now adds straight to
  Files; picked attachments are copied into app storage before sending.
