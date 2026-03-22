# Protocol

rmail uses JSON over HTTP (with TLS-PSK). There are two endpoints.

---

## Endpoints

**`POST /deliver`** — deliver a message or attachment payload:

```json
{"from": "alice", "token": "secret", "type": "message", "subject": "hello", "message_id": "uuid", "body": "text"}
```

**`POST /delete`** — notify of a deletion:

```json
{"from": "alice", "token": "secret", "message_id": "uuid"}
```

Auth is a shared secret per contact pair, checked against the contacts file.

### Message types

Every `/deliver` call includes a `type` field:

| `type`                | Direction         | Description                                   |
|-----------------------|-------------------|-----------------------------------------------|
| `message`             | sender → receiver | normal message delivery                       |
| `attachment_request`  | sender → receiver | consent request before file transfer          |
| `attachment_response` | receiver → sender | accept or decline a consent request           |
| `attachment_chunk`    | sender → receiver | one chunk of a file transfer                  |

Missing or unknown `type` values are rejected with 400.

---

## Testing with curl

```sh
curl -X POST http://localhost:8025/deliver \
  -H 'Content-Type: application/json' \
  -d '{"from":"alice","token":"your-shared-secret","type":"message","subject":"test","message_id":"test-1","body":"hello from curl"}'
```

Fill in the correct IP and port in place of `localhost:8025`.

To verify the daemon is reachable:

```sh
curl http://localhost:8025/
```

This returns `{"ok":true,"name":"yourname"}` if everything is working. You can
also test from another machine using the public IP to confirm port forwarding is
set up correctly.

---

## Sync timing

The daemon checks for outbox/inbox changes on an adaptive timer:

- Starts at **5 minutes**
- Had work: interval **shrinks by 4 min** (floor: 1 min)
- No work: interval **grows by 6 min** (no ceiling, resets on restart)

This means the daemon is responsive when you're actively messaging and backs
off when idle.

Attachment chunk transfers bypass the sync timer — once a transfer is in
progress, chunks are sent as fast as the connection allows within a single
sync pass.
