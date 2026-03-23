# Android App Plan

---

## Architecture

**Confirmed architecture:** Android → sender's home computer → receiver's home computer → receiver's Android (polls).

The phone submits messages to its own home daemon and never needs to be reachable. Delete/IP notifications flow between home daemons as normal.

**App design: file sync + text editor**

The app is a file sync layer over the home computer's mail directory, plus a minimal text editor. No special send logic — writing an outbox file with `to: alice\n\nbody` is all it takes. The home daemon picks it up on the next sync cycle.

Directory structure synced from home daemon:
```
inbox/       — received messages (phone can read and delete)
outbox/      — messages in flight (phone can create/delete)
contacts     — address book (phone can edit)
```

Received attachments live on the home server. The app shows a listing and streams/previews files on demand. The user can tap "Save to device" to download locally. Consent files appear in the inbox as normal files — the app detects their content and shows Accept/Deny buttons, rewriting the file accordingly.

---

## Tech stack

**Kotlin** (native Android). No Lua porting needed.

- `java.util.zip` — zip/unzip, built-in
- **BouncyCastle** (gradle dep) — TLS-PSK support; standard Android JSSE doesn't expose PSK via the normal API
- **OkHttp** — HTTP client
- **Jetpack Compose** — UI

---

## Sync protocol (phone ↔ home daemon)

Replace the REST CRUD API with a manifest-based file sync. Cleaner and consistent with the app's philosophy.

1. Phone POSTs a manifest: `{inbox: {filename: sha256, ...}, outbox: {...}, contacts: sha256}`
2. Server responds: `{fetch: [...], delete: [...], upload: [...], contacts: bool}`
3. Phone executes the diff — downloads fetched files, deletes local files, uploads new outbox files

**Deletion logic:** when a file is absent from the phone's manifest but present in the server's previous-sync record, the server treats it as an intentional delete and runs the normal delete-notification logic (sends `/delete` to the original sender). The server handles all special logic; the sync protocol just communicates what changed.

**Conflict resolution for contacts:** last-write-wins. Both sides include a timestamp on the contacts entry; the server keeps whichever is newer.

---

## Attachment upload from phone

The consent flow for received attachments is handled by the home daemon (phone just edits the consent file via sync). For sending attachments from the phone, a separate chunked upload protocol:

Two phases:
1. **Upload:** `POST /api/upload/start` with `{filename, num_chunks}` → returns `{upload_id, server_path}`. Server pre-creates the staging slot at `{attachments}/.uploads/<uuid>-filename`.
2. **Chunks:** `PUT /api/upload/{id}/chunk/{n}` for each chunk. Server auto-assembles when all `num_chunks` chunks have arrived — no explicit "complete" request needed.
3. **Compose:** app writes outbox file with `attach: <server_path>`. The phone path never appears on the server.

Always chunked — no threshold, no single-request path. Home daemon's regular sync then handles delivery using the existing consent + chunk protocol.

**Deletion of staged file:** the intermediate file in `.uploads/` is deleted when `release_zip` runs for the last active transfer referencing it. Config: `keep_phone_uploads = false` (default: delete; set `true` to keep a copy).

---

## Auth

The phone is registered in the contacts file as an own-device entry:

```
myphone.token = "phone-secret"
myphone.own   = true
```

`own = true` means "this is my own device" — it cannot be confused with a contact for another person. Own-device entries have no `ip` or `port` (the phone connects to you, not the reverse). The sync and upload APIs use TLS-PSK with the device token, same concept as regular contacts.

**Multiple phones:** all `own = true` entries access the same sync API and see the same mail directory.

---

## UI flow

**Inbox list → tap to open → read view**
- Back (top-left)
- Reply (top-right) → editor with `to: sender` pre-filled
- Swipe to delete (can be disabled in settings)
- Three dots menu → Delete / Forward / Save as PNG

**Compose → editor**
- X / cancel (top-left)
- Send arrow (top-right) → writes file to outbox/ on home daemon
- No explicit attachment button — user types `attach:` in the document body
  - A linter detects the bare `attach:` token and converts it to an inline button
  - The button is atomic: cannot place cursor inside it, deletes as a whole unit
  - Tapping it opens a picker window (choose file source: camera, gallery, files, etc.)
  - After selection, the button returns to text with the full filepath filled in: `attach: /sdcard/...`
  - Upload happens when the message is sent (send arrow tapped)

**Contacts → raw file editor**

---

## Forward behavior

Opens a new compose window. Template:

```
to:|                      ← cursor starts here
                          ← blank separator
                          ← blank line for user's own added text
                          ← blank separator
| to: alice
| to: bob
|
| Original message body here, each line prefixed with "| "
```

Each line of the forwarded message (including original `to:` lines) is prefixed with `| `. The user can delete or modify anything freely — no integrity guarantees.

---

## Save as PNG

Renders the message as a static image using the app's current theme colors. Saved to the device's gallery or shared via the system share sheet. No syntax highlighting — plain text rendered as-is.

---

## Theme / settings

Default theme: black background, goldenrod text.

Settings screen:
- Background color picker
- Text color picker
- Toggle: swipe to delete (default on)
