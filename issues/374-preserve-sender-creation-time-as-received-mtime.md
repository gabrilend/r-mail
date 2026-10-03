# #374 — Set received message file mtime to the sender's creation time

## Status

**Completed 2026-09-23.**  Built in commit d491ee8 ("Preserve message
authoring time (mtime) across transfer", 2026-08-03). The issue was filed on
2026-07-10 and was never closed after that commit landed.

How it was verified:

- **By running:** `scripts/test-authoring-time.sh` (written for this
  closing) runs two real daemons on loopback and checks every message path
  end to end: first delivery, an edit, a note to self, a phone upload
  delivered onward, and a phone download. It passed on three runs in a row
  on 2026-09-23.
- **By running, outside the script:** a `zip -j` / `unzip -o` round trip,
  the same pair of tools the attachment path uses, keeps a 2021 file date
  to the second. That is the basis for the attachments note below.
- **By reading:** the Android side (Kotlin client). No phone was
  involved. The test's phone stand-in speaks the same protocol from the
  server's side.

## Summary

When a message is received and written to `inbox/`, its file
modification time used to become "now", the moment the receiving
daemon called `write_file`. It is now set to **when the message was
created on the sender's machine**, so a file-manager / `ls -lt` view of
the inbox shows the order messages were written in, not the order they
were delivered in.

## Why

The inbox is "just files."  Users sort and scan by mtime.  A batch of
messages that were composed over days but all *received* in one sync
cycle used to collapse to the same timestamp, losing the real
chronology.  Keeping the original time makes the plain-files model
behave the way users expect from email.

## Current Behavior

A message's file date is carried across every hop a message file makes:

- **Daemon to daemon, first delivery.** When the sender builds a
  `deliver` operation for a new recipient, it reads the outbox file's
  modification time and puts it in the delivery payload as `mtime`
  (Unix epoch seconds). The payload is inside the AES-256-GCM
  encrypted request, so a man in the middle cannot change it without the
  request failing to decrypt. The receiver writes the inbox file, then
  stamps it with that time.
- **Daemon to daemon, edits.** When the sender sees that an already
  delivered message's body has changed, the `update` operation carries
  the outbox file's *current* modification time. The receiver rewrites
  the inbox file and re-stamps it. So an edited message moves to the time
  of the edit. That answers the "can it move backwards / only on first
  receipt" question below: it follows the sender's file, forwards or
  backwards.
- **Note to self.** Self-delivery and self-update copy the outbox file's
  time onto the inbox copy directly, with no network hop.
- **Phone upload.** The Android client sends `X-Mtime: <epoch seconds>`
  (the local file's `lastModified`) with `POST /api/file/outbox/<name>`.
  The daemon writes the outbox file and stamps it with that time. From
  there the file is an ordinary outbox file, so the first bullet carries
  the phone's compose time on to the recipient.
- **Phone download.** `GET /api/file/inbox/<name>` and
  `GET /api/file/outbox/<name>` return the file's time in an `X-Mtime`
  response header. The Android client stamps its local copy with it
  (`setLastModified`).  (Corrected 2026-10-02 by the documents-against-code
  audit, `notes/audit-docs-against-code-2026-10-02.md`: the phone's lists
  are sorted by file name, not by time, so the stamped time does not
  change their order.)
- **Older peers.** A sender that omits `mtime`, or a phone that omits
  `X-Mtime`, gets the old behaviour: the file is dated "now". No error is
  raised. (The owner's rules treat a silent fallback as a warning, so
  this is listed under open questions.)
- **Garbage times are ignored.** A time that is not a number, or falls
  outside 2001-09-09 .. 2100-01-01 (epoch 1000000000 .. 4102444800), is
  dropped and the file keeps "now".
- **Attachments** do not go through this mechanism. Between daemons an
  attachment travels as a zip archive, packed and read by rmail's own zip
  library since #405 (no `zip` or `unzip`).  The packer stores each file's
  modification time in the zip's extended-timestamp field (32 bits, so it
  wraps in 2038; the reader picks the wrap at or before the time of
  arrival) and the DOS time field (UTC, 1980–2107); the reader sets it on
  the extracted file, and the receiver files it with a rename, which keeps
  the time.  So daemon-to-daemon attachments keep their date.  Attachments
  uploaded from the phone (`/api/upload/start` then
  `PUT /api/upload/<id>/chunk/<n>`) are zipped by Java's `ZipEntry` with no
  extended time and carry no time header, so they are dated at upload.
  (Corrected 2026-10-02 from the documents-against-code audit; this
  section said `unzip` restored the time.)  See open questions.

## Intended Behavior

A message file's modification time means "when its author wrote it", on
every mailbox and device the message reaches. That time must survive:

1. delivery from one daemon to another;
2. a later edit, which re-dates the recipient's copy to the edit;
3. a note to self;
4. composing on the phone, uploading to the home daemon, and delivery
   onward, where the phone's compose time is the one that counts, not
   the upload time;
5. downloading to the phone.

The mechanism must not add a dependency. The daemon deliberately has no
LuaFileSystem, so reading and setting file times shells out to GNU
`stat` / `touch`, the same style as its existing `wc -c` calls.

## Suggested Implementation Steps

Everything is in `rmail.lua` unless another file is named.

1. **Two helpers**, placed right after `shell_quote`:
   - `file_mtime(path)` runs `stat -c %Y <path>` through `io.popen`.
     It returns a number (epoch seconds), or nil if the file is missing.
   - `set_file_mtime(path, epoch)` converts `epoch` with `tonumber`,
     ignores anything outside `1000000000 .. 4102444800`, then runs
     `touch -m -d @<epoch> <path>`. `-m` changes only the modification
     time, not the access time.
2. **Sender, new recipient** (`sync_outbox`, the branch that queues
   `type = "deliver"` for a recipient not yet in state): add
   `mtime = file_mtime(OUTBOX .. "/" .. name)` to the op.
3. **Sender, edit** (`sync_outbox`, the "detect body edits" block that
   compares `body_checksum`): add the same field to the queued
   `type = "update"` op.
4. **Sender, wire payload** (Phase 2 of `sync_outbox`, where `data` is
   built for `/deliver`): pass `mtime = op.mtime` in both the
   `type = "message"` and `type = "update"` tables.
5. **Receiver**: in `handle_deliver_message`, right after
   `write_file(target, body)`, add `if data.mtime then set_file_mtime(target,
   data.mtime) end`. Do the same in `handle_deliver_update` after its
   `write_file`.
6. **Self-delivery and self-update** (both in `sync_outbox`): after each
   `write_file(target, ...)`, add
   `set_file_mtime(target, file_mtime(OUTBOX .. "/" .. name))`.
7. **Phone API, server side**:
   - `handle_api_get_file` returns `file_mtime(...)` as a fourth value.
     The router for `GET /api/file/inbox/...` and `.../outbox/...` passes
     it to `send_raw_response` as the extra header `X-Mtime`.
   - `handle_api_post_outbox_file(filename, body, mtime)` takes the
     request's `x-mtime` header. It calls `set_file_mtime` after writing.
8. **Phone API, client side** (`clients/android/.../net/RmailClient.kt`,
   `data/MailStore.kt`, `sync/SyncManager.kt`):
   - `uploadOutboxFile` sends `X-Mtime` (seconds).
   - `downloadFileWithMtime` reads it back and converts it to milliseconds.
   - `MailStore.writeInbox` / `writeOutbox` call `setLastModified`.
9. **Test**: `scripts/test-authoring-time.sh`. It builds two mailboxes in
   `/tmp/rmail/tests/authoring-time` on ports 59420/59421. It plants
   outbox files with fixed past dates (`touch -d`) and checks the
   inbox copies with `stat -c %Y`. It includes a small Lua client that
   speaks the phone's encrypted frame format, for the upload and download
   cases.

## Decisions (resolving the original open questions)

The original questions are kept as asked, each followed by how the
build answered it:

- *Source of truth for `created`: outbox file mtime, or an explicit
  compose-time header the composer writes into the message?  Files get
  edited (mtime moves); an explicit header is more stable but needs
  composer support on every client.*
  → **Outbox file mtime.** An edit moving the time is treated as correct:
  the recipient's copy is re-dated to the edit. The field was named
  `mtime` rather than the `created` proposed below, because that is
  what it is.
- *Apply to **attachments** too, or messages only?*
  → Messages only, on purpose. Daemon-to-daemon attachments keep their
  time anyway through the zip archive (see Current Behavior). Phone
  attachment uploads do not. Still open, see below.
- *`touch -d @epoch` is GNU-specific.  Do we care about BSD/macOS daemon
  hosts (would need `touch -t` formatting)?*
  → Not handled. The build uses GNU `stat -c %Y` and `touch -d @N`. On a
  BSD/macOS host both would fail quietly and files would be dated "now".
- *Timezone/clock-skew: `created` is absolute epoch seconds, so TZ is a
  non-issue, but a sender with a wrong clock would set a wrong mtime.
  Accept as-is, or clamp to `<= now`?*
  → Accepted as-is, with a coarse sanity clamp to 2001..2100 to stop
  garbage or overflow. There is **no** clamp to `<= now`, so a sender
  whose clock runs fast can date a message in the future.
- *Should received mtime ever be allowed to move *backwards* on a later
  update to the same message, or only set once on first receipt?*
  → It follows the sender's file on every update, in either direction.

## Open questions carried forward

- **Phone-uploaded attachments** carry no authoring time. Should the
  chunk-upload API take an `X-Mtime` the way the outbox-file upload does?
- **Silent fallback to "now"** when a peer or phone omits the time, or
  sends one outside the sane range. The owner's rules count a silent
  fallback as a warning. Should the daemon log it?
- **BSD/macOS hosts**: accept that dates silently fall back to "now"
  there, or detect it?
- **Future dates** from a sender with a fast clock: clamp to the
  receiver's "now", or leave it?

## Found while verifying (not part of this issue)

Two daemon problems came to light while writing the test. Neither is in
the mtime code, and the test works around both, with comments saying so:

- **An edit made while the recipient is not due for contact is lost.**
  The per-contact timers (#377) hold back any request to a contact who
  is not yet due. The held-back request is reported to the op's builder
  as an ordinary failure, on the stated assumption that "every builder
  already treats failure as leave the op queued and change nothing".
  That is not true for edits. `sync_outbox` records the new
  `body_checksum` while it is *building* the update op, before anything
  is sent. So when the op is held back, the next cycle finds no
  difference and never sends the edit. The same thing happens to an
  edit made while the recipient is unreachable. The test makes its edit
  while the sender is stopped: at startup every contact is due, so the
  edit is sent at once.
- **Two daemons that dial each other at once both stall, and the
  receiver gets duplicate messages.** A daemon answers incoming requests
  only between its own outgoing ones. When A and B dial each other at the
  same moment, both sit out an 8-second timeout. A's delivery *was*
  written into B's inbox, but A records it as failed. On the next cycle
  A re-sends it with a **new** message id, and B files it as a separate
  message (`letter-64adf3`, `letter-22aade`, ...). In one run B's inbox
  collected eight copies in three minutes. The test avoids this by
  giving the receiver the sender's key but no address, so only one side
  dials.

## Origin

Filed 2026-07-10 in the batch #371-#375. Built 2026-08-03 (d491ee8).
Before that build, the deliver payload (`handle_deliver_message`) carried
`subject`, `message_id`, `body`, `attachments` and no timestamp. The
send-side op built `{message_id, subject, body}` with no time to send.
The daemon has no LuaFileSystem, so setting a file time meant shelling
out.

The original proposal, kept for the record:

1. **Sender:** add a `created` field (Unix epoch seconds) to the deliver
   payload, taken from the outbox file's mtime at send time, via
   `io.popen("stat -c %Y " .. shell_quote(path))`.
2. **Receiver:** after `write_file(target, …)` in
   `handle_deliver_message`, apply it with
   `os.execute("touch -d @" .. tonumber(data.created) .. " " .. shell_quote(target))`.
   Do the same for the self-delivery branch once #372 lands.

The build follows this almost exactly. The differences: the field is
`mtime`, `touch` gets `-m`, and the time is range-checked.

### The thin-client wrinkle (as originally written)

"Created on the sender's machine" is ambiguous for the Android
thin-client.  When the phone composes a message:

- The outbox file is *uploaded* to the server; its mtime **on the
  server** is upload time, not the phone's compose time.
- So sourcing `created` from the server-side outbox mtime gives *upload*
  time, not *authoring* time.

To keep the true authoring time for phone-composed messages, the
**client** must send its intended `created` timestamp when it uploads
the outbox file (the phone-created-outbox upload path), and the daemon
must honor it rather than re-stat the uploaded file.  For daemon-to-daemon
sends, the outbox mtime is the right source.

→ Built as described: the phone sends `X-Mtime` and the daemon stamps
the uploaded outbox file with it. From then on, "re-stat the outbox
file" returns the phone's time, so the daemon-to-daemon path needs no
special case.
