# Android App Plan

## Architecture

**Confirmed architecture:** Android → sender's home computer → receiver's home computer → receiver's Android (polls).

The phone submits messages to its own home daemon and never needs to be reachable by other peers. Delete/IP notifications flow between home daemons as normal.

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
- **`javax.crypto.Cipher`** (`AES/GCM/NoPadding`) — AES-256-GCM encryption, built into Android. No third-party crypto library needed. (Gradle is Android's standard build system — it manages library downloads, compilation, and APK packaging. Dependencies declared in `build.gradle` are downloaded automatically.)
- **`HttpURLConnection`** — HTTP client, built into Android. No third-party library needed; our request patterns are simple (POST manifest, GET file, PUT chunk). Each connection is wrapped in the custom AES-GCM encryption layer before transmission.
- **Jetpack Compose** — UI

---

## Auth

The phone is registered in the contacts file as an own-device entry:

```
myphone.token = "phone-secret"
myphone.own   = true
```

`own = true` means "this is my own device" — it cannot be confused with a contact for another person. Own-device entries have no `ip` or `port` (the phone connects to you, not the reverse). All sync and upload API calls are encrypted with the device token using the custom AES-GCM protocol.

No identity label is sent in cleartext. The server identifies the caller by trial decryption: it tries each known token in turn (own-device entries first, then contacts). The first token whose AES-GCM auth tag validates identifies the caller. An eavesdropper sees only destination IP and port — no names, no handshake labels. See the **Encryption protocol** section at the end for the full spec.

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
4. If unsuccessful, a message explains what to check: "Please verify your home computer's contacts file contains: `myphone.token = <your-token>` and `myphone.own = true`"

These settings are stored in app storage and editable later via the settings screen.

**First sync:** no previous sync state exists. Server sends all current inbox and outbox files as "fetch". Phone starts with a clean local copy.

**Home server IP changes:** if the home router's IP changes, the phone silently fails to connect. The phone does not attempt recovery automatically — it presents a troubleshooting screen: "Is the home server on? Is the rmail service running?" etc. One of the steps offers to query contacts for the current IP: "Your home IP may have been reassigned by your ISP. Ask your contacts?" The user confirms. The phone randomly selects at least 3 contacts and queries each via `GET /peer-address` using each contact's token for encryption — the server identifies the phone via trial decryption, no identity label sent. Responses are compared; the IP appearing in the majority is used. If no consensus, the phone reports failure. A malicious contact returning a wrong IP cannot hijack the phone: the subsequent sync requires TLS-PSK with the home daemon's token. The contact's daemon checks `allow_peer_address_requests` (config key, default `true`) before responding.

---

## Sync protocol (phone ↔ home daemon)

Message-ID-based sync, consistent with how the desktop daemon already tracks state in `inbox.json`. The phone maintains its own equivalent state file locally — no per-device history is stored server-side.

**Phone-side state:** `sync-state.json` — maps `{message_id: {filename, from}}` for all inbox messages currently on the phone, plus a list of known outbox filenames. Analogous to the desktop's `inbox.json`.

**Sync flow:**
1. Phone computes a local diff by comparing `sync-state.json` against current local files:
   - `deleted_inbox`: entries in state whose file no longer exists → user deleted them
   - `new_outbox`: local outbox files not in state → user created them
   - `deleted_outbox`: outbox filenames in state that no longer exist → user deleted them
2. Phone POSTs to `POST /api/sync` (authenticated via AES-GCM trial decryption):
   ```json
   {
     "inbox": {"message_id": "filename", ...},
     "deleted_inbox": [{"message_id": "...", "from": "..."}, ...],
     "outbox": ["filename.txt", ...],
     "deleted_outbox": ["old.txt", ...],
     "contacts_hash": "sha256..."
   }
   ```
3. Server processes deletions:
   - `deleted_inbox`: same logic as `sync_inbox` on the desktop — notifies each original sender's daemon to remove their `to:` line, cleans up associated attachments
   - `deleted_outbox`: same logic as `sync_outbox` — notifies recipients to delete
4. Server computes response by diffing against its current state:
   - `fetch_inbox`: server inbox entries whose message IDs are absent from the phone's `inbox` map → new messages for phone
   - `remove_inbox`: message IDs in phone's `inbox` map not found in server's `inbox.json` → deleted elsewhere (by desktop or another phone), phone removes local copy
   - `fetch_outbox`: server outbox files not in phone's `outbox` list → created on desktop, send to phone
   - `remove_outbox`: filenames in phone's `outbox` list not on server → sent/deleted, phone removes local copy
   - `contacts`: `"fetch"` if server's contacts are newer; `"upload"` if phone's are newer; `null` if same
5. Phone executes: downloads fetched files, deletes removed files, uploads new outbox files, syncs contacts
6. Phone updates `sync-state.json` only after all operations complete successfully

**No per-device state on server.** The phone provides enough context on each request for the server to compute the full diff against its own current `inbox.json` and outbox directory. No history of previous phone syncs is stored server-side.

**Deletion across devices:** phone A deletes inbox message X → phone A's `deleted_inbox` triggers the server to run delete-notification exactly once (removes X from server's `inbox.json`, notifies the original sender to remove their `to:` line). Phone B still has X locally; on its next sync, X's ID is in phone B's `inbox` map but absent from server's `inbox.json` → server puts X in `remove_inbox` → phone B deletes its local copy. No duplicate notifications.

**Interrupted sync:** naturally idempotent. Phone only updates `sync-state.json` after all operations complete. Next sync repeats any incomplete operations.

---

## Home daemon changes

All new code required in `rmail.lua`:

**New HTTP endpoints** (all require `own = true` device auth, verified via AES-GCM trial decryption):

- `POST /api/sync` — manifest sync (core endpoint)
- `GET /api/file/inbox/<filename>` — download inbox file to phone
- `GET /api/file/outbox/<filename>` — download outbox file to phone
- `POST /api/file/outbox/<filename>` — upload new outbox file from phone
- `GET /api/myaddress` — returns `{ip, port}`; daemon fetches IP from external services (same logic as dynamic IP detection)
- `GET /peer-address` — returns `{ip, port}` for the caller's own contacts entry. The server identifies the caller via trial decryption — no identity label is transmitted. The server looks up the matched token's contact name and returns that entry's stored address. Gated by `allow_peer_address_requests` config key (default `true`).

- `GET /api/attachments` — list filenames in attachments directory (JSON array)
- `GET /api/attachments/<filename>` — download attachment file to phone
- `POST /api/upload/start` — begin chunked attachment upload from phone
- `PUT /api/upload/<id>/chunk/<n>` — upload one chunk of a staged attachment

**Encryption layer:**
TLS/LuaSec is removed from rmail.lua entirely. Every connection — daemon-to-daemon and phone-to-daemon — uses the custom AES-GCM protocol. On the Android side, `javax.crypto.Cipher` (built-in) replaces BouncyCastle. On the Lua side, OpenSSL's AES-GCM is called directly (OpenSSL is already a dependency of LuaSec, so it remains available on disk — the change is calling it via FFI rather than the TLS socket abstraction). The trial decryption loop replaces the PSK callback entirely. See the **Encryption protocol** section for the full spec.

**`own = true` contact parsing:**
Own-device entries store only two fields: `token` and `own = true`. No `ip` or `port`. The contacts parser reads these fields already. Confirm that `load_contacts()` includes them in its returned table so the PSK callback can find them.

**Deletion logic integration:**
The phone sends deletions as direct `/delete` requests to its home server (same endpoint used between home servers), rather than bundling them in the sync request. The home server receives the request, recognizes the sender as an `own = true` device, and routes accordingly: removes the file from its inbox, notifies the original sender's daemon (so they can remove the `to:` line from their outbox), and any other attached own devices will receive `remove_inbox` on their next sync.

**Staged upload cleanup:**
Uploads from the phone go to `attachments/.uploads/<uuid>-filename`. Partial chunks are kept on interruption so the phone can resume — same behavior as interrupted desktop-to-desktop transfers (partial `.pending/` chunks persist until resumed or the transfer is cancelled). Once delivery to all recipients completes, `release_zip` deletes the staged file.

---

## Background sync and notifications

**Polling model:** the phone polls the home server on a schedule. The phone does not need to be reachable — no push channel required.

**Foreground:** while the app is open, poll every 15 seconds.

**Background:** Android's WorkManager enforces a minimum interval of 15 minutes for periodic background tasks. This is an OS-level constraint that cannot be overridden. Apps like WhatsApp get around it by using Firebase Cloud Messaging (FCM) — Google's push notification service maintains a persistent connection to Android devices and wakes apps on demand. Using FCM would introduce Google as a third party and is inconsistent with rmail's privacy model. WorkManager polling is the correct tradeoff.

**Doze mode:** Android aggressively defers background work when the device is idle. WorkManager respects Doze and cannot guarantee exact delivery times. Acceptable for this use case.

**Notifications:** when a sync finds new inbox files, the app posts a notification. Notification detail is configurable in settings — three levels: full (sender + subject), sender only, or no preview ("New message"). Default: sender + subject. Users who want their lock screen to reveal nothing can set no preview.

**Sync interval in settings:** configurable. Defaults: 15 seconds foreground, 15 minutes background. Phone sync is independent of the home server's own sync cycle — different systems, different mechanics.

---

## Attachments (receiving on phone)

Lazy download model. Attachments are not automatically synced to the phone — they stay on the home server until explicitly requested.

**Listing:** `GET /api/attachments` returns each file's name, size, broad type category (image / text / audio / other — not the specific format), and sender. These appear in an Attachments screen (separate from inbox). Each entry has a three-dots button that shows a detail panel with the full metadata.

**Download on demand:** user taps a filename to download it, then chooses to save to the gallery or file browser. No auto-downloading — all transfers to the phone device are explicit.

**Consent flow on phone:**
- Consent file arrives in inbox via normal sync — when the file is synced to the phone, not when the home server receives it
- App detects consent format when syncing: checks for lines containing `accept` and `deny`
- Detection happens at sync time, before the file appears in the inbox list
- When user opens the file, two large rectangular buttons fill the screen (half each, to prevent mis-taps): Accept (✓) and Deny (✗), with the consent information text above
- User has no keyboard — only the buttons
- Accept (✓): app rewrites consent file to contain only `accept`, syncs to server → home daemon proceeds with transfer
- Deny (✗): app rewrites with `deny`, syncs → home daemon cancels; consent file is then deleted
- Once accepted, the file transfers to the home server. It then appears in the Attachments screen listing. The user taps it there when they want to download it to the phone.

---

## Sending attachments from phone

When composing a message, the user types `attach:` in the body. The editor detects this token and converts it into an inline button. Tapping the button opens a file picker (camera, gallery, files). After selection, the button becomes `attach: /sdcard/...` as plain text.

**Upload on send:** when the user taps the send arrow, any `attach:` paths pointing to local files are uploaded to the home server before the outbox file is written to the server's filesystem.

Upload protocol:
1. `POST /api/upload/start` with `{filename, num_chunks}` → returns `{upload_id, server_path}`. The `/start` call registers the upload so the server can allocate a stable path (`attachments/.uploads/<uuid>-filename`) that the phone can reference in the outbox file before the upload is complete. The message body stays on the phone (in the compose draft) throughout the upload.
2. `PUT /api/upload/<id>/chunk/<n>` for each chunk, numbered 0 to num_chunks-1. The phone computed `num_chunks = ceil(filesize / chunk_size)` before calling `/start` and just sends all chunks in sequence. No manifest is involved — this is a direct upload loop.
3. Server auto-assembles when it has received all `num_chunks` chunks (tracked by count). No explicit complete request.
4. Phone writes the outbox file to the server with `attach: <server_path>`; the phone-local path never appears on the server.

Always chunked — no single-request path. The home daemon's regular sync then handles delivery to the recipient using the existing consent + chunk protocol.

---

## Contacts conflict resolution

The contacts file is a single text file edited directly via the phone's raw editor. Conflict scenario: user edits contacts on desktop and phone while both are offline; both diverge before the next sync.

**Resolution rule for v1:** phone wins. When the phone uploads a contacts file, it replaces the server's version. The server pushes its version to the phone only when the phone hasn't made local changes (hashes match since last sync).

**Editing contacts while offline:** when the phone can't reach the home server, the contacts editor is read-only (indicated by an offline status icon). If the user taps Edit, a message explains the situation and offers a "Create note-to-self" option. Tapping it prompts for a contact name, then opens a new draft in the inbox (no `to:` line, so it doesn't attempt delivery) pre-filled with:

```
please add this to the contacts file:

Alice.ip    =
Alice.port  =
Alice.token =
```

The user fills in the details while the information is fresh. When they get home, the note is in their inbox waiting. Automating the final step (parsing the note and inserting into the contacts file) is left as a future improvement — it would need robust parsing to avoid mishandling user-added notes in the same message.

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

**Attachments screen** — separate from inbox; similar from a UI standpoint. Lists filenames on home server; tap to download to device

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

## Multiple mailboxes

The app supports multiple completely independent mailbox configurations — for users running more than one rmail instance (different home servers, multiple household members sharing a device, or multiple use-cases (send scientific data to this inbox to be processed by these hooks, sent chatbot requests to this inbox to be updated and returned, send communication messages for this corporation or organization to this inbox, all on the same computer for the same human user).

Each mailbox has its own:
- Settings (home server address, port, device token)
- Local `sync-state.json`
- Contacts file copy
- Inbox / outbox / attachments views

A mailbox switcher (drawer or top-bar dropdown) lets the user switch between configured mailboxes. Adding a new mailbox follows the same onboarding flow as the first setup, but by default onboarding only initializes one inbox. Subsequent mailboxes can be created and onboarded afterwards.

---

## Encryption protocol

rmail uses AES-256-GCM over raw TCP. LuaSec and BouncyCastle are removed — see `rmail_crypto.c` and the daemon implementation in `rmail.lua` for the full spec.

Android uses `javax.crypto.Cipher` (`AES/GCM/NoPadding`) and `MessageDigest` (`SHA-256`), both built into the platform.
