# Attachments

rmail transfers files using a consent-first, chunked protocol. Every attachment
goes through the same pipeline regardless of size: the recipient is asked before
any bytes are transferred, and the file arrives in chunks of a zip (stored,
not compressed) that can be interrupted and resumed.

The message's text is held back until every attached path exists: a path
that is missing gets a `// MISSING ATTACHMENT: <path>` line under its
`attach:` line, and the message waits.  Deleting a message never deletes
the files it brought (#355).  A received file whose name is taken is saved
as `name-2.ext`, `name-3.ext`, …; a file identical to one already there is
kept once.

Limits: 4 GiB per file and per zip, 65,535 entries per zip (ZIP64 is not
read or written), at most 100,000 pieces per transfer.

The sender keeps, for every recipient and every attached path, that
recipient's answer — **complete**, **declined**, **cancelled**,
**withdrawn** or **lost** — in its outbox record.  A path is offered to a
recipient only while they have no answer for it (or it was withdrawn and
is back), so a file is never offered twice to someone who already has it
or said no.  The answer belongs to the path, not to the bytes: what is
sent is fixed when the file is first offered (#406, #408).

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

Both alice and bob are offered `photo.jpg`, whenever each is reached: if bob
is offline while alice finishes, he is offered it when he comes back.  The
`attach:` line stays as you wrote it.

**What is sent is fixed when first offered.**  The file is packed once,
when the first recipient is offered it, and every recipient gets that
packed copy — even if you change or delete the file afterwards.  The copy
is kept on disk, in the mailbox's pending folder, until every recipient has
answered, and removed then (#408).  To send a changed file, attach it under
a new path, or remove the line and put it back (below).

**Removing an `attach:` line withdraws the file.**  When a sync finds the
line gone, everyone who does not yet have the whole file stops getting it
and is told; their daemon removes the consent form or the pieces and
leaves a `withdrawn-<file>` note.  Anyone who already has it keeps it.  A
recipient who is offline is told when reached.  Removing the line and
putting it back before a sync notices changes nothing.  Putting it back
after a sync offers the file again to those it was withdrawn from — as a
new offer, packed from what is at the path then.  Changing the path is
withdrawing the old file and offering a new one: someone who declined the
old file is offered the new one (#406).

To send a file to only some recipients,
place the `attach:` line between their `to:` line and the next one:

```
to: alice
to: sarah
attach: /path/to/notes.pdf
to: bob

Alice and Sarah get the PDF, bob just gets the message body.
```

The path can point to a file or a directory. Directories are zipped recursively,
with their tree kept. If the path itself is a symbolic link, it is followed
once; links inside a directory are sent as links (never followed), and the
receiver turns each into a note (#405).
The original file is never modified or deleted.

---

## The consent flow

Before any data is transferred, the recipient sees a consent request appear in
their inbox, a file named `<message>-<file>-consent-to-download-form`:

```
alice wants to send you an attachment.

  Attached to:   photos-from-yesterday
  File:          photo.jpg
  Expected size: 3.2 MB
  Available:     47.3 GB on this drive
  After:         47.3 GB remaining (71% of capacity)

Delete one line and leave your choice behind for the system to read:

accept
deny
```

- **Delete `deny`** (leave `accept`): accept the transfer
- **Delete `accept`** (leave `deny`): decline

While both lines are present, the daemon treats the request as pending and
checks again on the next sync cycle. You can leave it for as long as you like.

The `Expected size` is the original uncompressed size, as reported by the
sender.  It is enforced: a transfer may take at most that size × 1.1 plus
4 KiB, both in the packed bytes that arrive and in the bytes the zip
unpacks to (measured before anything is written).  A transfer over either
limit is cancelled and nothing is kept.  (#327)

### After your decision

If you **accept**: the form becomes a progress file ("Sending: alice's
attachment photo.jpg is being transferred.", then a line per chunk; see
below), and the transfer begins when the sender is next due to sync with
you.  When the file is complete it is saved in `~/mail/attachments/` and
the form is removed.

If you **decline**: the form is removed, and the sender's daemon records
your answer and drops a `declined-<file>` notice in its own inbox.  That
file is never offered to you again from that message; other recipients are
not affected (#406).

If you **delete the consent file entirely**: this is treated as a decline.

---

## Transfer mechanics

The sender packs the file into a zip once, with rmail's own packer (the shared
zip library, #405; files are stored, not yet compressed), and splits it into chunks (default
5 MB each). Each chunk is sent as a separate request over the same AES-256-GCM
encrypted channel as messages. The receiver responds to each chunk with a list of still-
missing chunk indices, so chunks can be received in any order. The sender
continues until the missing list is empty, then marks the transfer complete.

If the file (or anything in the folder) is being written while it is
packed, the half-old, half-new zip is thrown away and the log says so:
`packing <path>: it changed while it was being packed -- will pack it again
next cycle`.  It is packed again on a later cycle, once it holds still.
(#404d)

Every chunk carries a SHA-256 checksum. Corrupted chunks are discarded and
re-requested automatically.

When all chunks have arrived, the receiver reassembles the zip, verifies the
total checksum, extracts the file, and fires the `on_package` hook (if
configured).

### What a received attachment is not allowed to do

A contact's zip is a claim about files, written by the contact.  The
receiving daemon checks it before anything reaches `attachments/`:

- **No symbolic links.**  A symbolic link is a tiny file whose content is
  a path; opening it opens whatever that path names, anywhere on the
  computer.  A link entry in a received zip is never recreated.  In its
  place is a plain note, `<name>.symlink.txt`:

  ```
  This was a symbolic link to: /home/alice/.ssh/id_rsa
  It was not recreated, because a link can point at any file on this computer. If it is valid here, make it by hand.
  ```

  Control characters in the target are written as `\xNN`.  If something
  in a received folder does not work, look for these notes; make the link
  yourself if it is one you want.  The zip reader never makes a link at
  all, so nothing can be written through one.  The phone is never served
  a link from `attachments/`, even one you made by hand.  (#404a, #405)
- **Checked whole before anything is made, and counted byte by byte.**
  Zips are read by rmail's own zip reader (the shared zip library in
  `libs/`, #405), not by `unzip`.  Before a single byte is made it
  refuses:
  - a name that climbs out of the folder (`..`) or starts at the root;
  - a name with a control character;
  - two entries on one path;
  - entries that share bytes (the "overlapping" zip bomb);
  - devices, pipes and sockets;
  - encryption;
  - damaged headers.

  It then counts every byte before it is made, so a zip that would
  unpack to more than the declared size plus 10% and 4 KiB stops at that
  limit, with nothing past it written (`oversize-unpacked`, #327).  Any
  refusal removes everything unpacked and cancels the transfer, and the
  record names the reason.
- **No piece without its checksums, and no changing the count.**  Every
  piece must carry the SHA-256 of itself and of the whole zip.  How many
  pieces there are, the whole zip's checksum and the length of a piece are
  fixed when piece 0 arrives; a later piece that disagrees is not stored,
  and the receiver asks for piece 0 again (which is also how a sender that
  had to pack the file anew starts over).  Every piece but the last must
  be exactly that length.  A piece may be as small as its sender likes,
  but no transfer may have more than 100,000 pieces, so a sender cannot
  declare a vast number of tiny ones.  Each answer lists at most 64 of the
  pieces still owed, with how many are held; the sender works through
  them batch by batch.  (#404b)
- **Files sent up from your phone are checked the same way.**  The phone
  declares the checksum of every piece and of the whole zip before it
  sends; each piece is checked as it arrives, the whole when it is
  complete.  The zip must hold exactly one regular file, whose size must
  fit the free space on the disk. If the zip reader cannot unpack it
  byte for byte, the upload is refused rather than filed half-done.
  (#404c, #405)
- **Nothing before your yes, and no strange ids.**  A piece that arrives
  while the consent form is still unanswered (or after you declined) is
  refused and nothing is written.  The id a contact gives an attachment
  names a folder on your drive, so only ids shaped like rmail's own (hex
  digits and dashes) are taken.  (#404e)

### In-progress visibility

While a transfer is running, the consent file in your inbox is updated after each
chunk arrives.  It is now a link into `/tmp/rmail-progress/` (in RAM, #328),
so the frequent rewrites never touch your disk:

```
Receiving photo.jpg from alice — 87 / 200 chunks (43%)
Average: 4.2 seconds per chunk.

To cancel: delete this file, or add a line that reads: deny
```

### Interrupted transfers

If the connection drops mid-transfer, the receiver keeps whatever chunks have
already arrived. The sender resumes from where it left off on the next sync
cycle — no re-negotiation, no new consent request needed.

Pieces wait on disk, in a hidden folder inside the mailbox,
`attachments/.pending/` (the `attachment_pending_dir` setting), so they
survive a restart or a reboot and the transfer resumes where it stopped.
The same folder holds the sender's packed copies (`rmail-<id>.zip`).  It
used to be `/tmp`, which on many systems is RAM: a reboot cleared partial
downloads, and a file arriving took room in RAM about three times over (the
pieces, the joined zip, the unpacked files).  What keeps arriving pieces
harmless is the checking above, not where they wait (#404f).  Being hidden,
nothing in it shows among your attachments or on the phone.

To keep them in RAM anyway, set `attachment_pending_dir` to a folder in
`/tmp`.  Write it in full: `~` is not expanded for this setting, and quotes
are kept.  A packed copy lost on a reboot is then **not** packed again
(that would send later recipients different bytes): the transfers stop and
a `// ATTACHMENT LOST: <path>` note under the `attach:` line says to remove
the line, wait for one sync, and put it back.

Pieces of a transfer that is never finished, and abandoned phone uploads,
are never cleaned up.

---

## Cancelling a transfer

**As the sender:** edit `~/mail/transfers`. It lists all active outgoing
attachments, one section per file, with a line per recipient showing progress:

```
--------------------------------------------------------------------------------
/home/alice/photos/photo.jpg

bob    5 / 12 chunks received
carol  awaiting consent
--------------------------------------------------------------------------------
```

Remove a recipient's line to cancel their transfer only — the file is still
sent to the other recipients and the outbox message is preserved.  Their
answer becomes *cancelled*, so the file is not offered to them again, and
their daemon is told, so their form or pieces go.  Remove the entire section
to cancel all recipients for that file.  Deleting the `transfers` file
cancels nothing: the daemon writes it again.  To stop sending the file to
everyone, removing the `attach:` line does the same (see "Sending an
attachment").

Deleting the outbox file also works and is more drastic: it sends a deletion
notice to all recipients, cancels any pending consent requests, stops any
in-progress chunk transfers, and removes the message from all inboxes.

**As the receiver (before accepting):** delete the consent file entirely, or
change `accept` to `deny`. Either way is treated as a decline.

**As the receiver (after accepting):** once the transfer starts, the consent
file is updated in-place with a progress report each time a chunk arrives:

```
Receiving photo.jpg from alice — 5 / 7 chunks (71%)
Average: 2.5 seconds per chunk.

To cancel: delete this file, or add a line that reads: deny
```

Delete that file (or add a `deny` line) to cancel. Partial chunks are
cleaned up on both sides.  The sender's daemon is told with a message
that names the attachment, not the message: it stops that one transfer and
records *cancelled*, and the message itself is untouched — you stay on it
and still get its edits (#407).  The same happens when your daemon refuses a
transfer (oversize, a damaged zip).

---

## Configuration

| Key                       | Default                 | Description                          |
|---------------------------|-------------------------|--------------------------------------|
| `attachments`             | `~/mail/attachments`    | where received files are saved       |
| `attachment_pending_dir`  | `<attachments>/.pending` | where arriving pieces and packed copies wait |
| `attachment_chunk_size`   | `5242880` (5 MB)        | bytes per chunk                      |

These are set in your mailbox's `config` file.  The generated config file does
not list them; add them by hand.  Write values plainly: quotes are kept as
part of the value and `~` is not expanded for these keys, and a quoted chunk
size silently falls back to the default.  Keep `attachment_chunk_size` below
about 37 MB: a chunk travels as base64 in one request, and requests over
50 MB are refused, so a larger chunk would never arrive.  Files sent up from
the phone always use 256 KiB pieces.

### Large message bodies

A message body (the text in your outbox file, below the headers) over 128 KB
(131,072 bytes) is sent as an attachment instead: the recipient gets a short
stub body and a consent form for the text, named after the message (#349).
Only if packing that attachment fails is an error written to your inbox.  An
edit to a message is sent as it is, with no size cap.
