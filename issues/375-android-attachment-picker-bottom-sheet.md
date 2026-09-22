# #375 — Android: attachment "+" bottom sheet with a Photo Picker route

## Problem

The Compose attachment section offers two `IconButton`s — a folder
picker and a file picker (`ComposeScreen.kt:306-311`):

```kotlin
IconButton(onClick = { dirPicker.launch(null) }) {
    Icon(Icons.Default.Folder, contentDescription = "Attach folder")
}
IconButton(onClick = { filePicker.launch(arrayOf("*/*")) }) {
    Icon(Icons.Default.Add, contentDescription = "Attach file")
}
```

Both route through the Storage Access Framework document picker
(`OpenDocument` / `OpenDocumentTree`).  For **images** this is a poor
experience: SAF's DocumentsUI defaults to sorting by name, and Android
gallery images have random/opaque filenames (`20260528_153135.jpg`,
content-hashes, etc.), so the list is effectively shuffled.  The app
**cannot** fix this — SAF sort order is a system-controlled,
per-user-persistent DocumentsUI preference with no launch-time override
(the only hint available is `EXTRA_INITIAL_URI` for the starting
folder, not sort).

The right picker for images is the **Android Photo Picker**
(`PickVisualMedia` / `PickMultipleVisualMedia`): it opens to the
gallery, is **most-recent-first by default**, supports multi-select
natively, and returns `content://` URIs that drop into the existing
upload flow.  minSdk is 26, and the Photo Picker is backported via
Google Play services, so it's available.

## Proposal

Replace the two icon buttons with a single **"+"** control that opens a
`ModalBottomSheet` (Compose's native slide-up window) offering the
picker choices, then routes to the right launcher.

### Bottom-sheet contents

Four rows, in order:

1. **Directory** → `dirPicker.launch(null)` (existing `OpenDocumentTree`)
2. **Image** → new `PickMultipleVisualMedia` launcher (gallery,
   recency-sorted, multi-select)
3. **File** → `filePicker.launch(arrayOf("*/*"))` (existing `OpenDocument`)
4. *(visual gap)*
5. **Cancel** → dismiss the sheet; rendered in **red**
   (`MaterialTheme.colorScheme.error`)

### Row styling

Rows are **not** icon buttons.  Each is a **full-width, pill-shaped
button** (fully rounded / circle edges, e.g. `RoundedCornerShape(50)`),
one per line, containing **text** — the label centered or leading, with
an **emoji at the far-left and far-right edges** of the button, padded
so they sit flush at the very start and very end of the row (a
space-between layout across the button's full width).  No Material
vector icons.

Suggested labels/emoji (final choice open):

```
📁   Directory        📁
🖼️   Image            🖼️
📄   File             📄

❌   Cancel           ❌     ← red
```

## Multi-select behavior

The **Image** row uses `ActivityResultContracts.PickMultipleVisualMedia()`
(optionally with a max), returning `List<Uri>`.  Its callback mirrors
the existing single-file callback (`ComposeScreen.kt:154-159`), adding
each URI as a `ComposeAttachmentEntry`:

```kotlin
for (uri in uris) {
    val name = resolveDisplayName(context, uri) ?: uri.lastPathSegment ?: "attachment"
    val mime = try { context.contentResolver.getType(uri) } catch (_: Exception) { null }
    attachments.add(ComposeAttachmentEntry(uri, name, mime))
}
```

Everything downstream is unchanged: the entries flow into the same list
and the same `vm.uploadAttachmentsInBackground(filename, attachments.map { it.uri })`
call (`ComposeScreen.kt:213`), which already ingests `content://` URIs.
So this feature does **not** depend on the `content://` fix noted in
[[372-loopback-attachments-via-chunk-system]] — that bug is on the
share-intent / older-client path, not the in-app picker.

(The existing single-select File and Directory pickers keep their
current single/tree behavior; only the new Image route is multi-select.)

## Scope / non-goals

- Same treatment likely wanted on the **InboxScreen** attachment entry
  points that also use `OpenDocument`/`OpenDocumentTree`
  (`InboxScreen.kt:211,222`) — check whether they share this UI or need
  the same bottom sheet.  Decide during implementation.
- No SAF sort "setting" — established as impossible; the Photo Picker
  makes it moot for the case that mattered (images).
- Requires an **APK rebuild** to reach the user (their installed client
  predates recent changes).

## Open questions

- Max selection count for `PickMultipleVisualMedia` — unlimited, or a
  cap (e.g. 30) to bound upload work?
- Exact labels, emoji, and whether the emoji should differ start vs end
  (the sketch repeats the same emoji on both edges).
- Should **File** also become multi-select (`OpenMultipleDocuments`)
  while we're here, or stay single to limit scope?
- Row text alignment — leading text with edge emoji, or centered text
  with edge emoji?
- Does the InboxScreen attachment UI get the same sheet, or is this
  Compose-only for v1?

## Status

**Implemented 2026-09-22, differently from the sketch above.**  The user
asked for an rmail dialog offering **Gallery** or **File**, after which
Android's own chooser asks *which* gallery or file app to use.  So:

- `AttachmentSourcePicker.kt`: one dialog used by every pick in the app
  (compose attach in both compose screens, Files `+`, Files Upload).
- Gallery = `ACTION_PICK` on MediaStore images (+ video MIME), multi-select,
  wrapped in `Intent.createChooser` -- gallery apps open newest-first.
- File = `ACTION_GET_CONTENT` `*/*` openable, multi-select, in a chooser.
  Not `OPEN_DOCUMENT`: that always goes to the system picker, so there would
  be no app to choose.  No starting folder is passed, so the system picker
  opens on Recent (newest first).  Sort order itself still cannot be set.
- The Photo Picker route was not used: it is not an app the user can
  choose between.  Folder attach (`OpenDocumentTree`) is unchanged.

**Later the same day:** a third source, **Camera** (`ACTION_IMAGE_CAPTURE`
into a FileProvider file under `files/camera/`, no CAMERA permission).  The
app picked for each source is remembered: the chooser reports it through
`EXTRA_CHOSEN_COMPONENT` and later taps launch it directly; long-pressing a
source asks again ("Long press to change default app").  A remembered app
that has been uninstalled is forgotten.

