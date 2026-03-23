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
inbox/       — received messages (read-only from phone)
outbox/      — messages in flight (phone can create/delete)
contacts     — address book (phone can edit)
```

**UI flow:**
- Inbox list → tap to open → read view
  - Back (top-left)
  - Reply (top-right) → editor with `to: sender` pre-filled
- Compose → editor
  - X / cancel (top-left)
  - Send arrow (top-right) → writes file to outbox/ on home daemon
  - Attachment button → file/image picker, triggers phone→home upload (see below)
- Contacts → raw file editor (with auto-backup before save)

**Attachments from phone:**

Phone acts as sender, home computer acts as receiver for the upload leg using the existing chunked transfer protocol. Home computer stores the uploaded file locally. Outbox file gets `attach: /path/to/uploaded-file`. Home daemon then handles delivery to the recipient as normal (consent + chunk transfer). Two hops: phone → home (upload), home → recipient (existing protocol).

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
| `PUT` | `/api/contacts` | overwrite contacts file (home daemon backs up old version first) |

For attachment upload: reuse the existing `/deliver` endpoint with type `attachment_chunk`, authenticated as a device contact. The home daemon receives the file into a staging area (e.g. `~/mail/attachments/.uploads/`), and the phone-side compose flow inserts `attach: /path/to/staged/file` into the outbox file.

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
