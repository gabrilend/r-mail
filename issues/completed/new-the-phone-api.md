# #new-the-phone-api — The home daemon's door for the owner's own devices

## Status

Completed — a blueprint written 2026-10-04 (#402) for what was built
before issue files described it.  Everything the phone (phase 8) and the
desktop thin client (#329) do goes through it.

## Current Behavior

The phone is not a mail server: it cannot be reached, and it sleeps.  It
is a window onto the **home daemon's** mailbox.  In the home mailbox's
contacts it is an ordinary contact with a token and `own = true`
(#new-the-contacts-file); every request it makes is a sealed frame like
any contact's (#new-encrypted-frames).  Paths under `/api/` answer only
a contact marked `own` (403 for anyone else):

| request | what it does |
|---|---|
| `POST /api/sync` | the phone says what it has; the daemon answers what to fetch and remove (below) |
| `GET /api/file/inbox/<f>`, `GET /api/file/outbox/<f>` | one file, with its modification time in `X-Mtime` |
| `POST /api/file/outbox/<f>` | a message written on the phone, dated by `X-Mtime`; the daemon sends it like any outbox file |
| `GET /api/contacts`, `POST /api/contacts` | the contacts in canonical form; a save is merged into the file (#411) |
| `POST /api/consent` | answer a consent form `accept` or `deny` by its name; the sender is tried at once |
| `GET /api/attachments` | the received files: name, size, kind, sender, SHA-256 (no links, #404a) |
| `GET /api/attachments/<f>/info`, `.../chunk/<n>`, `GET /api/attachments/<f>` | download a file in 256 KiB pieces with their checksums, or whole |
| `DELETE /api/attachments/<f>` | delete a received file |
| `POST /api/upload/start`, `/resume`, `PUT /api/upload/<id>/chunk/<n>` | send a file up in pieces, each checked, resumable (#105, #404c) |
| `GET /api/myaddress` | the home daemon's public and LAN addresses, port and name |
| `POST /api/log` | a line from the phone, written into the daemon's log |

**The sync exchange.**  The phone sends: its inbox (message id ->
file), the inbox messages it deleted, its outbox file names, the outbox
files it deleted, and the hash of its contacts copy.  The daemon:
deletes what the phone deleted (an inbox deletion is then told to the
sender, as if made at home; deleting a consent form declines it), and
answers with what the phone lacks (`fetch_inbox`, `fetch_outbox`), what
it should drop (`remove_inbox`, `remove_outbox`), the contacts text when
the hashes differ, and the mailbox's name and path.  The home mailbox is
the record; the phone converges on it.

## Intended Behavior

As above.  #200 sketches finer-grained access for other shared devices.

## Suggested Implementation Steps

1. `rmail.lua`, "Phone API endpoints": `handle_api_sync`,
   `handle_api_get_file`, `handle_api_post_outbox_file`,
   `handle_api_get_contacts`, `handle_api_post_contacts`,
   `handle_api_list_attachments`, `handle_api_attachment_info`,
   `handle_api_attachment_chunk`, `handle_api_get_attachment`,
   `handle_api_delete_attachment`, `handle_api_myaddress`,
   `handle_api_log`, `upload.start` / `resume` / `chunk` / `finish`;
   the `/api/` table and the consent answer in `handle_request`.
2. Tests: `scripts/test-phone-upload-checks.sh`,
   `scripts/test-phone-contacts-save.sh`, `scripts/test-received-links.sh`.

## Related documents

- `docs/.templates/android-instructions.md`, `docs/.templates/protocol.md`
- `#105`, `#200`, `#404c`, `#411`
