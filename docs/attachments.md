# Attachments

rmail transfers files using a consent-first, chunked protocol. Every attachment
goes through the same pipeline regardless of size: the recipient is asked before
any bytes are transferred, and the file arrives in compressed chunks that
can be interrupted and resumed.

---

## Sending an attachment

Add an `attach:` line to your outbox file, below the `to:` line for the
recipient you want to receive it:

```
to: alice
to: bob
attach: /path/to/photo.jpg

Here's the photo from yesterday.
```

Both alice and bob get `photo.jpg`. To send a file to only some recipients,
place the `attach:` line between their `to:` line and the next one:

```
to: alice
to: sarah
attach: /path/to/notes.pdf
to: bob

Alice and Sarah get the PDF, bob just gets the message body.
```

The path can point to a file or a directory. Directories are zipped recursively.
The original file is never modified or deleted.

---

## The consent flow

Before any data is transferred, the recipient sees a consent request appear in
their inbox:

```
alice wants to send you an attachment.

  File:          photo.jpg
  Expected size: 3.2 MB
  Available:     47.3 GB on this drive
  After:         47.3 GB remaining (71% of capacity)

Delete one of these lines to make your choice:

yes
no
```

- **Delete `no`** (leave `yes`): accept the transfer
- **Delete `yes`** (leave `no`): decline

While both lines are present, the daemon treats the request as pending and
checks again on the next sync cycle. You can leave it for as long as you like.

The `Expected size` is the original uncompressed size, as reported by the
sender. rmail is a trust-based system — the value is not independently
verified before transfer.

### After your decision

If you **accept**: the transfer begins automatically on the next sync cycle.
When complete, the consent file is replaced with a confirmation:

```
Transfer complete:
alice's attachment photo.jpg has arrived.
Saved to: ~/mail/attachments/photo.jpg
```

If you **decline**: the consent file is replaced with a notice, and the
sender's daemon removes the `attach:` line from their outbox file and drops
a declined notice in their own inbox.

If you **delete the consent file entirely**: this is treated as a decline.

---

## Transfer mechanics

The sender compresses the file (zip) once and splits it into chunks (default
5 MB each). Each chunk is sent as a separate request over the same TLS-encrypted
channel as messages. The receiver responds to each chunk with a list of still-
missing chunk indices, so chunks can be received in any order. The sender
continues until the missing list is empty, then marks the transfer complete.

Every chunk carries a SHA-256 checksum. Corrupted chunks are discarded and
re-requested automatically.

When all chunks have arrived, the receiver reassembles the zip, verifies the
total checksum, extracts the file, and fires the `on_package` hook (if
configured).

### In-progress visibility

While a transfer is running, a STATUS file is updated with each received chunk:

```
photo.jpg: 87 / 200 chunks (43%) — last received: 2026-03-21 14:32
```

Find it at `~/mail/attachments/.pending/<transfer-id>/STATUS`.

### Interrupted transfers

If the connection drops mid-transfer, the receiver keeps whatever chunks have
already arrived. The sender resumes from where it left off on the next sync
cycle — no re-negotiation, no new consent request needed.

Whether partial chunks survive a reboot depends on `attachment_pending_dir`:
- **`/tmp`** (default): the OS clears partial downloads on reboot. The sender
  will restart from the beginning on reconnect.
- **A persistent path** (e.g. `~/mail/attachments`): chunks survive reboots
  and the transfer resumes exactly where it left off.

---

## Cancelling a transfer

To cancel a transfer in progress, delete the outbox file. This sends a
deletion notice to all recipients, which cancels any pending consent requests
and stops any ongoing chunk transfer.

You cannot cancel an individual attachment without cancelling the whole message.
To remove a recipient after sending, remove their `to:` line from the outbox
file — but any attachment transfer already in progress for that recipient
continues until the file is received or they decline.

---

## Configuration

| Key                       | Default                 | Description                          |
|---------------------------|-------------------------|--------------------------------------|
| `attachments`             | `~/mail/attachments`    | where received files are saved       |
| `attachment_pending_dir`  | `/tmp`                  | where in-progress chunks are stored  |
| `attachment_chunk_size`   | `5242880` (5 MB)        | bytes per chunk                      |

These are set in `~/.config/rmail/config`. The config file has a comment above
each key explaining it.

### Message body size limit

Message bodies (the text in your outbox file, below the headers) are capped at
128 KB. If you try to send a larger body, the daemon writes an error to your
inbox and won't retry that message. Use an `attach:` line instead.
