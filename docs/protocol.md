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
METHOD /path HTTP/1.0\r\n
Content-Length: N\r\n
\r\n
body
```

Responses follow the same format with a status line:

```
HTTP/1.0 200 OK\r\n
Content-Length: N\r\n
\r\n
body
```

JSON bodies use `Content-Type: application/json`.

---

## Endpoints

### Authenticated (any contact with a valid token)

**`POST /deliver`** — deliver a message or attachment payload:

```json
{"type": "message", "subject": "hello", "message_id": "uuid", "body": "text"}
```

**`POST /delete`** — notify of a deletion:

```json
{"message_id": "uuid"}
```

**`POST /update-address`** — notify of an IP change:

```json
{"ip": "203.0.113.1", "port": 8025}
```

**`GET /peer-address`** — returns the caller's stored IP:port (for IP recovery).

### Own-device only (contacts with `own = true`)

These require the caller's contact entry to have `own = true` set.

**`POST /api/sync`** — manifest exchange for phone/device sync.

**`GET /api/file/inbox/<f>`** / **`GET /api/file/outbox/<f>`** — download files.

**`POST /api/file/outbox/<f>`** — upload an outbox file.

**`GET /api/contacts`** / **`POST /api/contacts`** — read/write contacts file.

**`GET /api/attachments`** / **`GET /api/attachments/<f>`** — list/download attachments.

**`POST /api/upload/start`** / **`PUT /api/upload/<id>/chunk/<n>`** — chunked upload.

**`GET /api/myaddress`** — returns the daemon's public IP, port, name, and LAN IP.

### Unauthenticated (plaintext, no encryption)

**`GET /`** — health check. Returns `{"ok":true,"name":"yourname"}` in plain HTTP.
Used by `validate-router-settings.sh` to test connectivity.

### Message types

Every `/deliver` call includes a `type` field:

| `type`                | Direction         | Description                          |
|-----------------------|-------------------|--------------------------------------|
| `message`             | sender -> receiver | normal message delivery              |
| `attachment_request`  | sender -> receiver | consent request before file transfer |
| `attachment_response` | receiver -> sender | accept or decline a consent request  |

Missing or unknown `type` values are rejected with 400.

---

## Sync timing

The daemon checks for outbox/inbox changes on an adaptive timer:

- Starts at **5 minutes** (currently set lower for development)
- Had work: interval **shrinks** (floor: MIN_INTERVAL)
- No work: interval **grows** (ceiling: MAX_INTERVAL)

This means the daemon is responsive when you're actively messaging and backs
off when idle.

Attachment chunk transfers bypass the sync timer — once a transfer is in
progress, chunks are sent as fast as the connection allows within a single
sync pass.

A manual sync can be triggered by creating the file `<mailbox>/.state/sync-now`.
