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

**`POST /delete`** — notify of a deletion:

```json
{"message_id": "uuid"}
```

(Today a receiver's attachment cancellation is also sent as `/delete` with the
message's id, which the sender cannot tell from a deletion — #407.)

**`POST /update-address`** — announce this mailbox's addresses (every start-up,
and after an IP change):

```json
{"ip": "203.0.113.1", "port": 8025, "ips": ["203.0.113.1"], "local_ips": ["192.168.1.20"]}
```

`ip` and `port` are kept for older peers; `ips` and `local_ips` are the full
sets (a configured `hostname` first).

**`GET /peer-address`** — returns the caller's stored IP:port (for IP recovery).
Refused when `allow_peer_address_requests = false`.

**`GET /deps`**, **`GET /deps/<name>`**, **`GET /install-script`** — the
dependency list, one dependency, and the installer, for a contact building
rmail.

### Own-device only (contacts with `own = true`)

These require the caller's contact entry to have `own = true` set.

**`POST /api/sync`** — manifest exchange for phone/device sync.

**`GET /api/file/inbox/<f>`** / **`GET /api/file/outbox/<f>`** — download files.

**`POST /api/file/outbox/<f>`** — upload an outbox file.

**`GET /api/contacts`** / **`POST /api/contacts`** — read/write contacts file.

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

**`GET /`** — health check. Returns `{"ok":true,"name":"yourname"}` in plain HTTP
to anyone who connects, so it reveals the mailbox's name (#410 removes it).
Used by `validate-router-settings.sh` to test connectivity (it only needs an
answer).

### Message types

Every `/deliver` call includes a `type` field:

| `type`                | Direction         | Description                          |
|-----------------------|-------------------|--------------------------------------|
| `message`             | sender -> receiver | normal message delivery              |
| `update`              | sender -> receiver | a new version of a message (the author edited it) |
| `attachment_request`  | sender -> receiver | consent request before file transfer |
| `attachment_response` | receiver -> sender | accept or decline a consent request  |
| `attachment_chunk`    | sender -> receiver | one piece of an accepted attachment  |
| `chunk_failed`        | either             | answered `ok`, nothing else          |

Missing or unknown `type` values are rejected with 400.

---

## Sync timing

Each contact has its own timer (#377):

- **Floor 30 seconds.**  A contact is due 30 s after a successful exchange.
- **Each failed cycle adds 6 minutes** (360 s), up to a **ceiling of 2 hours**.
- **±30 seconds** of random jitter on every wait.
- A contact that connects to us is due **at once**; a contact with nothing
  queued goes back to the floor; **every contact is due at start-up**.

A change in the outbox is noticed at once (inotify on Linux, kqueue on the
BSDs and macOS) and starts a sync pass, but each contact is still only sent
to when its own timer is due (#396 is open about this), and attachment pieces
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
