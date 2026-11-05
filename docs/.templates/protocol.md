# Protocol

rmail communicates over raw TCP connections encrypted with AES-256-GCM. There
is no TLS — encryption is handled directly at the application layer using a
symmetric key derived from a shared token.

---

## Wire format

Every message (request or response) is a single encrypted frame:

```
[4 bytes: big-endian payload length]
[12 bytes: nonce]
[ciphertext + 16-byte GCM authentication tag]
```

The **payload length** covers the nonce + ciphertext + tag (everything after the
4-byte length prefix).

### Key derivation

The encryption key is `SHA-256(token)` where `token` is the shared secret
between two contacts (from the contacts file). Both sides use the same key.

The receiving daemon performs **trial decryption** — it tries each known
contact's key until one succeeds. This identifies the sender without requiring
an unencrypted identity header.

### Plaintext content

Inside the encrypted frame, the plaintext is HTTP-style:

```
POST /path HTTP/1.1\r\n
Host: <ip>:<port>\r\n
Content-Type: application/json\r\n
Content-Length: N\r\n
Connection: close\r\n
\r\n
body
```

Responses follow the same format with a status line (`HTTP/1.1 200 OK`).
The daemon keeps a connection open for further frames from the same
caller.  JSON bodies use `Content-Type: application/json`.

Limits: a frame is 28 bytes to 64 MiB; a request body over 50 MB is refused.

### A frame sent from a web page

A web page cannot put bare bytes on a connection: the browser always
writes a request line and headers in front of what the page sends, and
the page can neither remove nor reorder them.  So a page sends its frame,
all of it including the 4-byte length, as the body of a plain web POST:

```
POST / HTTP/1.1\r\n            <- written by the browser
Host: ...\r\n
Content-Length: 4 + frame length\r\n
\r\n
[4 bytes length][nonce][ciphertext + tag]   <- the frame, unchanged
```

The daemon tells the two apart by the first byte of the connection.  A
legal frame length (28 bytes to 64 MiB) always starts with a byte from
0x00 to 0x04; a web request starts with a capital letter, 0x41 or above.
For a POST it skips the headers, checks that the declared Content-Length
is exactly 4 plus the frame's own length (refused with `400` if not), and
then reads the frame like any other: the same trial decryption, the same
endpoints, nothing extra allowed.  The sealed answer comes back as the
body of a `200` web reply, and the connection closes.

A page sending this way has to hold a contact's token to seal the frame.
A page served over `https://` may only send to an `http://` address on
the same machine (`localhost`), by the browsers' rule against mixing
secure and insecure content.  Tested by
`scripts/test-frame-in-web-request.sh`.

Nothing protects against replay: a recorded frame stays valid and can be
sent again later (a `/delete`, an `/update-address`, or a `/deliver` of a
message the receiver has since deleted).

---

## Endpoints

### Authenticated (any contact with a valid token)

**`POST /deliver`** — deliver a message or attachment payload:

```json
{"type": "message", "subject": "hello", "message_id": "uuid", "body": "text",
 "mtime": 1790000000}
```

`mtime` is the sender's outbox-file modification time (seconds since 1970);
the receiver sets it on the inbox file, clamped to 2001-09-09 … 2100-01-01
(a missing or out-of-range value becomes "now").  An `update` (an edited
message) carries the same fields.  `auto_body` marks a large body sent as an
attachment (see attachments, "Large message bodies").

A `subject` with no `/` is a file name, made safe as it always was (only what
follows the last `\` kept, leading dots dropped, control characters made
`_`, spaces made `-`).
A `subject` holding `/` (#214: a message from the sender's contact folder,
`projects/q2-plan.md`) names folders below the receiver's inbox, which are
made as needed.  It is refused with `400` and nothing written when it is
absolute, has an empty name (`a//b`, `a/`), a `.` or `..`, a name starting
with `.`, any control byte (NUL and DEL included), a name over 255 bytes,
more than 16 levels, or over 1024 bytes in all; or when a folder on the way
is a symbolic link, or the folders resolve outside the inbox.  When a file
holds one of the folder names, the message is saved without its folders.
An older receiver keeps only the last name, as it always did.

**`POST /delete`** — notify of a deletion:

```json
{"message_id": "uuid"}
```

Cancelling one attachment is not a deletion: it is its own message,
`attachment_cancel` (below), which names the attachment and leaves the
message alone.

**`POST /update-address`** — announce this mailbox's addresses (every start-up,
and after an IP change):

```json
{"ip": "203.0.113.1", "port": 8025, "ips": ["203.0.113.1"], "local_ips": ["192.168.1.20"]}
```

`ip` and `port` are kept for older peers; `ips` and `local_ips` are the full
sets (a configured `hostname` first).

**`GET /deps`**, **`GET /deps/<name>`**, **`GET /install-script`** — the
dependency list, one dependency, and the installer, for a contact building
rmail.

### Listen-only contacts (`listen = true`)

A contact marked `listen = true` — a website's, whose token is in every
page — may send exactly one kind of request: `POST /deliver` whose JSON
holds only `type` (= `"message"`), `subject`, `body` (text, at most 64
KiB), `message_id` and `mtime` (a number).  Every other request from it,
bare or inside a web POST, is answered `403` with the reason, logged, and
changes nothing; that includes `/delete`, `/update-address`, the `/deps`
family, an `update`, a message with `attachments` or `auto_body`, and the
sealed `GET /`.  The daemon never sends anything to such a contact.

### Own-device only (contacts with `own = true`)

These require the caller's contact entry to have `own = true` set.

**`POST /api/sync`** — manifest exchange for phone/device sync.

**`GET /api/file/inbox/<f>`** / **`GET /api/file/outbox/<f>`** — download files.

**`POST /api/file/outbox/<f>`** — upload an outbox file.

**`GET /api/contacts`** / **`POST /api/contacts`** — read the contacts in
sorted form with no comments; save that form back after editing.  A save is
merged into the file: only contacts that differ are changed, comments and
blank lines stay, and the merged file must read back as exactly what was
posted or nothing is written (answer 500).

**`GET /api/attachments`** / **`GET /api/attachments/<f>`** — list/download attachments.

**`GET /api/attachments/<f>/info`** / **`GET /api/attachments/<f>/chunk/<n>`** —
an attachment's size and checksums, and one piece of it (the phone's resumable
download).

**`DELETE /api/attachments/<f>`** — delete a received attachment.

**`POST /api/consent`** — answer a consent form from the phone.

**`POST /api/log`** — the phone writes a line into the daemon's log.

**`POST /api/upload/start`** / **`POST /api/upload/resume`** /
**`PUT /api/upload/<id>/chunk/<n>`** — chunked upload (256 KiB pieces), resumable.

**`GET /api/myaddress`** — returns the daemon's public IP (and IPv6), port, name, and LAN IP.

The phone is sent the whole contacts file, every contact's token included.

### Unauthenticated (plaintext, no encryption)

**`GET /`** — health check. Returns `{"ok":true}` in plain HTTP to anyone who
connects — nothing about the mailbox, so it can test a port forward from
outside without the token.  Used by `validate-router-settings.sh` to test connectivity (it only needs an
answer).

**Any other web method** (`PUT`, `DELETE`, `OPTIONS`, ...) — answered
`405 Method Not Allowed` with `Allow: GET, POST`, and logged.

**Everything else is disregarded** — closed at once with nothing said,
and one line in the log.  That is: a first byte that is neither a frame
length (0x00–0x04) nor a capital letter (a TLS hello, lower case, 0xFF,
anything between); capitals that are not method-shaped (three capitals,
then a capital or a space); and a web request whose request line and
headers do not end within 16 KiB.  None of these is waited on.

### Message types

Every `/deliver` call includes a `type` field:

| `type`                | Direction         | Description                          |
|-----------------------|-------------------|--------------------------------------|
| `message`             | sender -> receiver | normal message delivery              |
| `update`              | sender -> receiver | a new version of a message (the author edited it) |
| `attachment_request`  | sender -> receiver | consent request before file transfer |
| `attachment_response` | receiver -> sender | accept or decline a consent request  |
| `attachment_chunk`    | sender -> receiver | one piece of an accepted attachment  |
| `attachment_cancel`   | either             | `{attachment_id}`: stop this one transfer.  From the receiver: they cancelled or refused it (the sender records *cancelled*).  From the sender: the author withdrew it (the receiver drops its pieces and form, and leaves a `withdrawn-<file>` note).  The message is untouched.  404 when there is no such transfer. |
| `chunk_failed`        | either             | answered `ok`, nothing else          |

Missing or unknown `type` values are rejected with 400.

Any request may be answered `503` with `{"busy": true}`: the receiving
daemon was in the middle of sending to the caller itself.  It is not an
answer to the request — the caller retries it at its next sync (about 30
seconds), without backing off and without trying the contact's other
addresses.  Without it, two daemons that had something for each other at
the same moment each waited out the other's timeout.

---

## Sync timing

Each contact has its own timer (#115):

- **Floor 30 seconds.**  A contact is due 30 s after a successful exchange.
- **Each failed cycle adds 6 minutes** (360 s), up to a **ceiling of 2 hours**.
- **±30 seconds** of random jitter on every wait.
- A contact that connects to us is due **at once**; a contact with nothing
  queued goes back to the floor; **every contact is due at start-up**.

A change in the outbox is noticed at once (inotify on Linux, kqueue on the
BSDs and macOS) and starts a sync pass, but each contact is still only sent
to when its own timer is due (#119 is open about this), and attachment pieces
pass through the same gate.

Other timings: connecting to a contact gives up after 8 s; receiving waits
10 s, sending 30 s; DNS answers are kept 60 s; an automatic port mapping is
renewed every 30 minutes (NAT-PMP lifetime 1 hour); the public IP is checked
every 24–48 hours (an hour later if no provider answered).  `rmail.lua <mailbox>
--once[=SECONDS]` runs one round of syncing for 60 s by default (up to 600 s
more while transfers finish) and exits.

The phone syncs in the background every 15 minutes (the shortest period
Android allows), and in the foreground uses the same 30 s / +6 min / 2 h
back-off.
