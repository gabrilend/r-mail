# Miscellaneous Improvements Plan

---

## Android app

### Architecture

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

**UI flow:**
- Inbox list → tap to open → read view
  - Back (top-left)
  - Reply (top-right) → editor with `to: sender` pre-filled
  - Swipe to delete (can be disabled in settings)
  - Three dots menu → Delete / Forward / Save as PNG
- Compose → editor
  - X / cancel (top-left)
  - Send arrow (top-right) → writes file to outbox/ on home daemon
  - No explicit attachment button — user types `attach:` in the document body
    - A linter detects the bare `attach:` token and converts it to an inline button
    - The button is atomic: cannot place cursor inside it, deletes as a whole unit
    - Tapping it opens a picker window (choose file source: camera, gallery, files, etc.)
    - After selection, the button returns to text with the full filepath filled in: `attach: /sdcard/...`
    - Upload happens when the message is sent (send arrow tapped)
- Contacts → raw file editor

**Forward behavior:**

Opens a new compose window. Template:

```
to:
                          ← blank line (cursor starts here for "to:" entry)

                          ← blank line for user's own added text

                          ← blank separator

| to: alice
| to: bob
|
| Original message body here, each line prefixed with "| "
```

Each line of the forwarded message (including original `to:` lines) is prefixed with `| ` to indicate it is a forward. The user can delete or modify anything freely — no integrity guarantees. The four lines at the top give the user space for new recipients and an optional note before the quoted text.

**Save as PNG:**

Renders the message as a static image using the app's current theme colors. The image can be saved to the device's gallery or shared via the system share sheet.

Rendering rules:
- Background and text colors: inherited from app theme settings
- Text between `"..."`: rendered in a distinct quote color
- Text between ` ``` ... ``` ` or inline `` ` `` : rendered in a code color (monospace font)
- Other formatting markers can be added as the feature matures

**Theme / settings:**

Default theme: black background, goldenrod text.

Settings screen includes:
- Background color picker
- Text color picker
- Quote color picker (for `"..."`)
- Code color picker (for backtick blocks)
- Toggle: swipe to delete (default on)

**Attachments from phone — upload flow:**

Two phases:
1. **Upload:** app uploads the file to the home daemon. Home daemon stores it in `~/mail/attachments/.uploads/<uuid>-filename`. API returns the server-side path.
2. **Compose:** app writes the outbox file with `attach: /home/user/mail/attachments/.uploads/<uuid>-filename`. The phone path never appears on the server.

Home daemon's regular sync then handles delivery to the recipient using the existing consent + chunk protocol. Two hops: phone → home (upload), home → recipient (existing protocol).

**Deletion of uploaded file:**
The intermediate file in `.uploads/` is deleted when `release_zip` runs and finds no more active transfers referencing that zip — i.e., when all recipients have completed or cancelled the transfer. This reuses existing cleanup logic.

Config option: `keep_phone_uploads = false` (default: delete after all transfers done). Set to `true` to keep a copy on the home computer.

**Upload staging directory:** `.uploads/` subdirectory inside the configured attachments directory (i.e. `{attachments}/.uploads/`). Persistent across reboots, inside the mail directory, separate from received attachments. Follows the user's `attachments` config key automatically.

**Upload API:** a dedicated upload endpoint rather than reusing the chunked transfer system (no consent flow needed for authenticated device uploads):

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/upload` | upload a file (small files, single request) |
| `POST` | `/api/upload/start` | start chunked upload → returns `upload_id` |
| `PUT` | `/api/upload/{id}/chunk/{n}` | upload one chunk |
| `POST` | `/api/upload/{id}/complete` | finalize → returns server-side path |

For files under a configurable threshold (e.g. 5 MB), single-request upload is fine. Larger files use the chunked path.

**Auth:** The phone is added to the contacts file as a device entry:
```
myphone.token = "phone-secret"
myphone.type  = device
```
Management API uses TLS-PSK with the device token — same concept users already understand.

**Multiple phones:** All device-type contacts access the same management API and see the same mail directory.

**Management API needed (home daemon):**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/inbox` | list inbox files (name, from, subject, timestamp) |
| `GET` | `/api/inbox/{filename}` | read a message |
| `DELETE` | `/api/inbox/{filename}` | delete (triggers delete notification to sender) |
| `GET` | `/api/outbox` | list outbox files |
| `PUT` | `/api/outbox/{filename}` | write/create an outbox file |
| `DELETE` | `/api/outbox/{filename}` | delete outbox file |
| `GET` | `/api/contacts` | read contacts file |
| `PUT` | `/api/contacts` | overwrite contacts file |
| `POST` | `/api/upload` | single-request file upload |
| `POST` | `/api/upload/start` | start chunked upload |
| `PUT` | `/api/upload/{id}/chunk/{n}` | upload one chunk |
| `POST` | `/api/upload/{id}/complete` | finalize upload, returns server path |

**Android app plan doc:** `android-app-plan.md` — create separately.

---

## Receiver cancellation of in-progress attachment transfer

**Fix: implement the functionality.**

The consent file in the inbox is updated in-place as chunks arrive. The user always has one file to look at (the same one they used to accept), and deleting it cancels the transfer.

Progress format (written to the consent file after each chunk):
```
Receiving photo.jpg from alice — 5 / 7 chunks (71%)
Average: 2.5 seconds per chunk.

Delete this file to cancel and clean up partial downloads.
```

Implementation:
1. Keep the `consent-pending.json` entry alive after acceptance, marking status `"receiving"`. The `inbox_file` path is already stored there.
2. On each received chunk in `handle_attachment_chunk`, overwrite the consent file with updated progress text.
3. On each sync cycle in `check_consent_pending`, scan `"receiving"` entries: if the inbox file is gone, send `/delete` to the sender with the `message_id`. The sender's existing `handle_delete` cancels outgoing chunks.
4. On transfer complete, replace the consent file with the completion notice. Remove entry from `consent-pending.json`.

Files to change:
- `rmail.lua` — implement steps above
- `docs/attachments.md` — update cancellation section (already updated with placeholder wording; finalize after implementation)
- `README.md` — update one-liner cancellation description

---

## UPnP warning: once-ever vs per-contact

**Implemented** in `rmail.lua`. See commit history.

Design summary (for reference):
- `nat_security_warned.json` tracks warned contacts individually (name → timestamp).
- Each startup probes the router. If vulnerable, sends warning only to contacts not yet warned.
- If no longer vulnerable and `nat_security_vulnerability_active` exists, sends "fixed" notice to all previously warned contacts, resets both state files.

---

## Does a local IP in the contacts file leave the router / go through the ISP?

**No.** Private IPs (192.168.x.x, 10.x.x.x, 172.16–31.x.x) are non-routable. From outside the LAN the connection just fails — packets never leave the sender's router, ISP never sees them. Harmless from a privacy perspective; just won't connect from the outside.

Worth a note in the docs to explain why.
