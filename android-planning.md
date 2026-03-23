# Android App Plan

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

Received attachments live on the home server. The app shows a listing of filenames and lets the user download files on demand. Consent files appear in the inbox as normal files — the app detects their content and shows Accept/Deny buttons instead of the raw text.

---

## Tech stack

**Kotlin** (native Android). No Lua porting needed.

- `java.util.zip` — zip/unzip, built-in
- **BouncyCastle** — TLS-PSK support. Standard Android (JSSE) doesn't expose PSK via the normal TLS API, so BouncyCastle provides its own TLS stack. Added as a Gradle dependency. (Gradle is Android's standard build system — it manages library downloads, compilation, and APK packaging. Dependencies declared in `build.gradle` are downloaded automatically.)
- **OkHttp** — HTTP client
- **Jetpack Compose** — UI

---

## Auth

The phone is registered in the contacts file as an own-device entry:

```
myphone.token = "phone-secret"
myphone.own   = true
```

`own = true` means "this is my own device" — it cannot be confused with a contact for another person. Own-device entries have no `ip` or `port` (the phone connects to you, not the reverse). The sync and upload APIs use TLS-PSK with the device token.

The PSK client identity label (sent during the TLS handshake) is the device's entry name (e.g., `myphone`). The server receives this label, looks up `contacts[name]` where `own == true`, and returns the corresponding token as the PSK key.

**Multiple phones:** all `own = true` entries access the same sync API and see the same mail directory.

---

## Onboarding / first-time setup

Before using the app, the user must add a device entry to their contacts file on their home computer:

```
myphone.token = "some-long-random-secret"
myphone.own   = true
```

When the app is first installed:
1. Setup screen prompts for:
   - Home server address (public IP or hostname)
   - Port (same port rmail is listening on)
   - Device token (must match the token in the contacts file)
2. Tap "Connect" — app performs first sync
3. If successful, inbox appears and normal use begins

These settings are stored in app storage and editable later via the settings screen.

**First sync:** no previous sync state exists. Server sends all current inbox and outbox files as "fetch". Phone starts with a clean local copy.

---

## Sync protocol (phone ↔ home daemon)

Manifest-based file sync. The phone tracks its previous sync state locally so the server can detect intentional deletions vs files the phone never had.

**Sync flow:**
1. Phone builds a current manifest: `{inbox: {filename: sha256, ...}, outbox: {filename: sha256, ...}, contacts: sha256}`
2. Phone POSTs manifest to `POST /api/sync` (TLS-PSK authenticated)
3. Server compares manifest against its stored per-device "last known state" and the server's current file system
4. Server responds: `{fetch: [filenames], delete: [filenames], upload: [filenames], contacts: "fetch"|"upload"|null}`
5. Phone executes the diff:
   - Downloads each file in `fetch` from the server
   - Deletes local files in `delete`
   - Uploads each file in `upload` to the server
   - If `contacts == "fetch"`: downloads server's contacts file
   - If `contacts == "upload"`: uploads phone's contacts file
6. Phone updates its local `sync-state.json` with the current manifest (only after all operations succeed)

**Server decision logic:**
- **fetch** (server → phone): file is on the server but not in the phone's last-known manifest → new for this device
- **delete** (remove from phone): file was in the phone's last-known manifest but no longer on the server (deleted by desktop user or another device)
- **upload** (phone → server): file is in the phone's current manifest but not in the phone's last-known manifest → phone created this file
- **deletion detection**: file was in phone's last-known manifest, not in phone's current manifest → intentional delete by phone user → server runs delete-notification logic (sends `/delete` to original sender) and removes file from inbox

**Server per-device state:** stored in `.state/device-<name>.json`. Contains the last manifest the server saw from this device. Updated after each successful sync.

**Interrupted sync:** naturally idempotent. Phone only updates `sync-state.json` after all operations complete successfully. If the connection drops mid-sync, the next sync repeats the same operations.

**Deletion across devices:** when phone A deletes a message, the server removes it from inbox and sends `/delete` to the sender. Phone B, on its next sync, receives it in the `delete` list and removes it locally. The `/delete` notification to the sender fires only once (when the file is first removed from the server inbox), not again when other devices sync.

---

## Home daemon changes

All new code required in `rmail.lua`:

**New HTTP endpoints** (all require `own = true` device auth via TLS-PSK):

- `POST /api/sync` — manifest sync (core endpoint)
- `GET /api/file/inbox/<filename>` — download inbox file to phone
- `GET /api/file/outbox/<filename>` — download outbox file to phone
- `POST /api/file/outbox/<filename>` — upload new outbox file from phone
- `GET /api/myaddress` — returns `{ip, port}`; daemon fetches IP from external services (same logic as dynamic IP detection)
- `GET /api/attachments` — list filenames in attachments directory (JSON array)
- `GET /api/attachments/<filename>` — download attachment file to phone
- `POST /api/upload/start` — begin chunked attachment upload from phone
- `PUT /api/upload/<id>/chunk/<n>` — upload one chunk of a staged attachment

**PSK identity routing:**
The server's PSK callback must handle multiple device identities. When a device connects, it sends its name as the PSK identity label. The server looks up `contacts[name].token` where `contacts[name].own == true`. This may require restructuring the existing per-contact PSK logic.

**Per-device sync state:**
Read/write `.state/device-<name>.json` on each sync request.

**`own = true` contact parsing:**
The contacts parser already reads the `own` field. Verify the daemon actually loads and stores `own = true` entries — they have no `ip` or `port` and may currently be skipped by connection-oriented code paths.

**Deletion logic integration:**
When a file disappears from a device's manifest compared to its last-known state, run the same delete-notification code path used for desktop inbox deletions.

**Staged upload cleanup:**
Intermediate files in `attachments/.uploads/` are deleted when `release_zip` runs for the last active transfer referencing them. Config: `keep_phone_uploads = false` (default: delete; `true` keeps a copy).

---

## Background sync and notifications

**Polling model:** the phone polls the home server on a schedule. The phone does not need to be reachable — no push channel required.

**Foreground:** while the app is open, poll every 30 seconds.

**Background:** Android's WorkManager enforces a minimum interval of 15 minutes for periodic background tasks. This is an OS-level constraint that cannot be overridden. rmail's model is closer to email than instant messaging, so 15-minute background delivery is acceptable.

**Doze mode:** Android aggressively defers background work when the device is idle. WorkManager respects Doze and cannot guarantee exact delivery times. This is acceptable for the email-like use case.

**Notifications:** when a background sync finds new inbox files, the app posts a notification ("New message from Alice"). Notification shows the sender name and subject (filename). Tapping opens the message.

**Sync interval in settings:** configurable. Default: 30 seconds foreground, 15 minutes background. Reading the home server's sync interval from the config file adds complexity with little benefit — sensible defaults are sufficient.

---

## Attachments (receiving on phone)

Lazy download model. Attachments are not automatically synced to the phone — they stay on the home server until explicitly requested.

**Listing:** during sync, the app fetches the attachment filename list from `GET /api/attachments`. These appear in an Attachments screen (separate from inbox).

**Download on demand:** user taps a filename and chooses to save to the gallery or file browser. App downloads from `GET /api/attachments/<filename>`.

**Consent flow on phone:**
- Consent file arrives in inbox via normal sync (it's just a regular inbox file)
- App detects consent format: checks for lines containing `accept` and `deny`
- Detection happens when the file is received, before it appears in the inbox list
- When user opens the file, Accept (✓) and Deny (✗) buttons appear where those lines would be
- User has no keyboard at this point — only the buttons
- Accept: app rewrites consent file to contain only `accept`, syncs to server → home daemon proceeds with transfer
- Deny: app rewrites with `deny`, syncs → home daemon cancels; consent file is then deleted

**Auto-download after accept on phone:** when the user accepts consent on the phone, the home daemon begins receiving the file from the sender. Once the transfer completes, the file appears in `attachments/` on the home server. The phone should automatically download it at that point rather than just adding it to the listing. Mechanism: on each sync, the app checks for new entries in the attachment listing that match recently-accepted consent filenames; if found, downloads automatically to local storage.

---

## Sending attachments from phone

When composing a message, the user types `attach:` in the body. The editor detects this token and converts it into an inline button. Tapping the button opens a file picker (camera, gallery, files). After selection, the button becomes `attach: /sdcard/...` as plain text.

**Upload on send:** when the user taps the send arrow, any `attach:` paths pointing to local files are uploaded to the home server before the outbox file is written.

Upload protocol:
1. `POST /api/upload/start` with `{filename, num_chunks}` → returns `{upload_id, server_path}`; server pre-creates staging slot at `attachments/.uploads/<uuid>-filename`
2. `PUT /api/upload/<id>/chunk/<n>` for each chunk
3. Server auto-assembles when all chunks received (no explicit complete request)
4. Outbox file is written with `attach: <server_path>`; the phone-local path never appears on the server

Always chunked — no single-request path. The home daemon's regular sync then handles delivery to the recipient using the existing consent + chunk protocol.

---

## Contacts conflict resolution

The contacts file is a single text file edited directly via the phone's raw editor. Conflict scenario: user edits contacts on desktop and phone while both are offline; both diverge before the next sync.

**Resolution rule for v1:** phone wins. When the phone uploads a contacts file, it replaces the server's version. The server pushes its version to the phone only when the phone hasn't made local changes (hashes match since last sync).

This is a rare edge case. If it becomes a problem in practice, add per-entry timestamps and merge by last-write-wins per entry.

---

## UI flow

**Inbox list → tap to open → read view**
- Back (top-left)
- Reply (top-right) → editor with `to: sender` pre-filled
- Swipe to delete (can be disabled in settings)
- Three dots menu → Delete / Forward / Save as PNG

**Compose → editor**
- X / cancel (top-left)
- Send arrow (top-right) → uploads attachments if any, writes outbox file to home daemon
- No explicit attachment button — user types `attach:` in the document body
  - A linter detects the bare `attach:` token and converts it to an inline button
  - The button is atomic: cannot place cursor inside it, deletes as a whole unit
  - Tapping it opens a picker window (choose file source: camera, gallery, files, etc.)
  - After selection, the button returns to text with the full filepath filled in: `attach: /sdcard/...`

**Contacts → raw file editor**
- "My address" button (top-right or toolbar) — displays the user's public IP and port so they can tell a new contact what to put in their contacts file. The IP must come from the home daemon, not the phone — the phone would return the mobile carrier's IP, which is wrong. Implementation: a new `GET /api/myaddress` endpoint on the daemon returns `{ip, port}`; the daemon fetches the IP from its usual external services (`ifconfig.me`, `icanhazip.com`, etc.), the same logic already used for dynamic IP detection. The app calls this endpoint and displays the result.

**Attachments screen** — separate from inbox; lists filenames on home server; tap to download to device

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
- Home server address
- Home server port
- Device token
- Background sync interval (default: 15 min; OS minimum enforced)

---

## Open questions

1. **PSK identity routing in LuaSec:** does the current LuaSec TLS-PSK server implementation support a callback that receives the client's identity label and returns the matching key? This is required for the server to handle multiple devices with different tokens. Needs verification before implementing the server-side sync endpoint.

2. **Interrupted attachment upload from phone:** if the chunked upload is interrupted mid-way (e.g., chunk 3 of 10 arrives, then connection drops), does the server discard partial data and require a restart, or keep the chunks and allow resumption from where it left off? Resume is better UX but more complex to implement — decide before building the upload endpoint.

3. **Auto-download trigger after phone accept:** when an accepted attachment finishes transferring to the home server, how does the phone know it's ready? Options: (a) poll the attachment listing each sync and match against recently-accepted consent filenames; (b) server includes a "ready" flag in the sync response for newly-completed transfers. Which approach?

4. **Delete-notification deduplication across devices:** when phone A deletes a message, the server sends `/delete` to the sender once. If phone B still has the file and syncs later, the server should not send a second `/delete`. Confirm the delete-notification code path only fires when the file is first removed from the server inbox, not when a device is told to remove its local copy.

5. **Device entry setup during onboarding:** the user must manually add the device entry to the contacts file before first app sync. Should the install script or rmail.lua offer a helper command (e.g., `lua rmail.lua --add-device myphone`) to generate the entry, or is a documentation note sufficient?
