# #902 — Send message body as a fixed-chunk attachment for size obfuscation

## Current Behavior

Wire-level padding (#901) blunts size disclosure for short messages,
but it does so per-message with diminishing returns as messages get
larger.  The existing hook-based padding example in
`docs/encryption.md` only pads *up to* a target length — anything
longer passes through at its natural size:

```sh
if [ "$current" -lt "$target" ]; then
    # pad to target
else
    echo "${body}"    # no-op — size leaks out
fi
```

For users who want *stronger* size obfuscation — the kind where a
1 KB message and a 1 MB message look indistinguishable on the wire
— the right tool is rmail's existing attachment pipeline.  Every
attachment is compressed, split into **fixed-size chunks**
(`cfg.chunk_size`, default 5 MiB), and delivered chunk-by-chunk.
Each chunk is the same size on the wire regardless of what it
contains.  Take a message of any size, pad it to a multiple of
the chunk size, send it as an attachment, and the size of every
chunk is fixed — an observer sees only how many chunks went.

## Intended Behavior

Add an `on_send` hook (or a daemon-level config flag — see
"Open question" below) that transforms an outgoing message into:

- A small, fixed-size *stub* body containing just routing/subject
  info and a pointer to the attached file, OR a blank body.
- The real message content written to a temp file, padded with
  random bytes to the next `cfg.chunk_size` multiple, and queued
  through the normal attachment pipeline.
- A receiver-side `on_receive_raw` or `on_receive` hook strips the
  padding trailer and restores the body.

The stub body itself should be padded to a fixed power-of-2 size
via #901 so the stub chunk doesn't leak the subject length.

### Trailer format

The padded attachment contains:

```
[real message bytes]
-------------------------------------------------------------------------------
    end of encrypted message. what follows is random data with no meaning.
-------------------------------------------------------------------------------
[random bytes, ASCII-safe, to next chunk-size multiple]
```

The receiver's hook slices at the trailer marker and keeps only
the real message bytes.  The marker is visible in plaintext
*only* after decryption — observers on the wire see the sealed
ciphertext, which is always the same number of chunks.

### Chunk size as the unit of disclosure

With `cfg.chunk_size = 5 MiB`, every message discloses only "how
many 5 MiB chunks" — a 10 KB text and a 4 MB text both go out as
one chunk (same bytes on wire).  A 6 MB text and an 8 MB text both
go out as two chunks.  That's still some signal but a much coarser
one.  Users who want finer-grained normalization can set a smaller
chunk size at the cost of per-chunk overhead.

### Composition with #901

#901 handles the short-message case (pad to nearest power of 2
inside the single encrypted frame).  #902 handles the long-message
case (send as padded attachment of fixed-size chunks).  Together:

- Messages below the bucket threshold get size-obfuscated by #901.
- Messages above the threshold get size-normalized by #902 at the
  chunk granularity.
- Neither blocks the other; a user can enable #901 unconditionally
  (it's transparent) and #902 only when they want maximum
  normalization.

## Open questions

### Hook or daemon config?

Two places this could live:

1. **Pure hook recipe** — document it in `docs/encryption.md`'s
   "Mitigating traffic analysis" section, include the exact
   `on_send` / `on_receive` scripts.  No daemon changes.  Users
   opt in per-mailbox.
2. **Daemon config flag** — e.g.
   `privacy.body_as_padded_attachment = true` in the config,
   which makes the daemon do the transform internally.  Easier
   for users, more moving parts.

Prefer (1) for now.  The hook system is powerful enough for this
and keeps the daemon simple.  If enough users want it,
daemon-level follows.

### What about replies / forwards seeing the trailer text?

If the receiver's `on_receive_raw` strips correctly, the body
stored in `~/mail/inbox/<subject>` is clean.  Reply/forward
quoting uses that clean body (see `msg.content` in the Android
ReadScreen path).  So the trailer only ever lives in the padded
on-wire payload and a short window between decrypt and
`on_receive_raw` on the receiver.

### What if the receiver has no matching `on_receive_raw` hook?

Then the trailer text ends up in the receiver's inbox file —
ugly, but not a security issue.  The doc should be clear that
both parties need to configure the hooks.  Tooling idea for a
future pass: a shared "privacy preset" script users can drop
into both sides' mailboxes that installs the hooks in one step.

## Non-goals

- **Defeating traffic analysis entirely.**  Timing, chunk counts
  per message, and send frequency are still visible.  Decoy
  traffic (already in `encryption.md`) addresses timing; nothing
  here targets that.
- **Hiding attachment semantics at a different layer.**  rmail's
  attachment pipeline already has its own consent/ack flow;
  a padded body looks like any other attachment to that layer.
  We don't try to make it indistinguishable from a "real" user
  attachment.

## Suggested Implementation Steps

- The `on_send` hook's stdout replaces the outgoing body (see
  `hooks.on_send` usage around `rmail.lua:3370` in the current
  tree).  The hook needs to *also* write the padded attachment
  into a location the outbox file references via `attach:` — or,
  the hook emits a stub body and the user's workflow includes
  explicit `attach:` lines.  Work out the exact glue when
  prototyping.
- The padding is random bytes ASCII-encoded so the attachment
  is safely text-handleable by any downstream hook that assumes
  text — or drop the ASCII-safe constraint and just use raw
  bytes (the pipeline treats attachments as opaque binary
  anyway).  Probably raw bytes; simpler and the trailer marker
  is enough to delimit.
- Document heavily — this is a subtle feature with two-sided
  configuration.  Any mistake leaves the feature silently
  ineffective.

## Source

Identified 2026-04-19 while reviewing `docs/encryption.md`.  The
existing hook-based padding example stops working past the target
length, and the author had already sketched the
body-as-attachment idea in an inline comment: *"we could do it
with text manipulation in the hook, so an outgoing message is
replaced with the same message included as an attachment with a
fixed-size padding trailer."*

## Status

Built 2026-11-05 as the issue's option 1, a hook recipe, waiting for the
owner's checks.  `helpers/rpad.sh` (sending) and `helpers/runpad.sh`
(receiving, from `on_package`), and the two hooks in
`docs/.templates/encryption.md`, "Sending the body as a padded
attachment".  No daemon change.  Test: `scripts/test-padded-body.sh`,
which takes the hooks from the guide itself.  Stacked on #901.

## Decisions (2026-11-05)

Made by the builder; the owner can overturn each.

1. **A helper the owner runs, not an `on_send` hook.**  `on_send` runs per
   recipient at send time and can only replace the body; by then the
   attachments are already planned, so it cannot add one.  So the sending
   half is `rpad.sh <mailbox> <draft>`: the owner writes the message as a
   draft outside the outbox (where the daemon would send it at once) and
   rpad writes the outbox file, moved in whole.  The receiving half is
   hooks, as the issue asks: `on_consent` (#216) accepts the padded file
   and `on_package` (#216's `$4`) puts the words back.
2. **A fixed file name, `message.padded-body`, in `padded/<name>/`.**  The
   zip's headers hold the name twice, so a name that changed with the
   message would change the attachment's size by its length.  With one
   name, every padded message's zip is the same size until it outgrows a
   piece (61594 bytes for 64 KiB pieces in the test).  The folder is in
   the mailbox, not /tmp: a big file is sent from where it lies (#317).
3. **Padded to whole pieces less 4 KiB,** not to whole pieces: the zip
   adds its headers (about 150 bytes), and a file of exactly whole pieces
   would spill a tiny extra piece.  The last piece is then always the same
   size.  Pieces smaller than 16 KiB keep a quarter of a piece instead.
4. **Raw random bytes after the marker** (the issue's "probably raw
   bytes"), and the receiver cuts at the **last** marker, so a message
   that quotes the marker keeps every word; random bytes never spell it.
   The marker is written on its own lines after a newline that is part of
   the marker, so a message with no last newline comes back exactly.
5. **The words go back into the inbox file in place** (same file, same
   name), so the inbox record, the phone and reply/forward all see the
   message as written.  Until the file arrives the inbox holds the fixed
   short body, which says what is happening and where to look if the hooks
   are missing.  With no inbox file the words go beside the padded file.
6. **`on_consent` accepts only up to 64 MiB.**  The file name is no secret,
   so any contact could use it to skip the consent form; a cap keeps that
   from being a way to push large files unasked.  Larger ones wait for the
   owner as usual.
7. **No daemon config flag** (option 2), as the issue prefers for now.
