# #new-a-message-is-a-file — A message is a file: written in one outbox, it appears in another's inbox

## Status

Completed — a blueprint written 2026-10-04 (#402) for what was built
before issue files described it.  The foundation of phase 2.

## Current Behavior

**Writing.**  A message is a plain text file in `outbox/`.  Its name is
its subject.  It opens with a header — `to:` lines naming recipients by
their contact names, `attach:` lines naming files, blank lines and `//`
comments allowed among them (#363) — and the first line that is none of
those starts the body:

    to: alice
    to: bob
    attach: ~/photos/hoodie.jpg

    The text of the message.

A `to:` line's `attach:` lines are those after it (#new-consent-before-any-byte).
`attach:` paths take `~` (#101) and wildcards (#362).

**Sending.**  Each cycle (#new-the-sync-cycle) the outbox is compared
with the outbox record (`.state/outbox.json`: per file, per recipient,
the message id that recipient has).  A recipient with no record is sent
the message — `POST /deliver` `{type = "message", subject, message_id,
body, mtime}` — with a new random message id, once every attached path
exists (until then the message waits and a `// MISSING ATTACHMENT` note
says why).  `mtime` is the file's modification time, so the copy is
dated when it was written, not when it arrived (#374).  On success the
recipient is recorded with its message id.  A `to:` line naming no
contact gets a `// UNKNOWN CONTACT` note; a name that is both this
mailbox's own and a contact's is refused with `// AMBIGUOUS RECIPIENT`
rather than guessed.

**To oneself.**  `to:` the mailbox's own name (#394) is written straight
into its own inbox, through the same hooks, with no network.

**Receiving.**  The message becomes `inbox/<subject>` with the body as
sent (leading blank lines dropped), dated by `mtime`, recorded in the
inbox record (`.state/inbox.json`: file name -> who sent it, message id).
A name already taken gets a suffix: `-from-<sender>` when another sender
has it, a piece of the message id when the same sender sent a different
message (#315).  Names are cleaned of anything that could make a path.

**After.**  Edits travel (#306, #409); deletes travel both ways
(#new-deletes-travel-both-ways); a body over 128 KB travels as an
attachment (#349).  When every recipient has been struck off (they all
deleted it), the outbox file is deleted — but never one whose `to:` line
named nobody resolvable, which keeps its note for the author.

## Intended Behavior

As above.

## Suggested Implementation Steps

1. `rmail.lua`: `_scan_outbox_header`, `parse_outbox_file`;
   `sync_outbox` (new recipients, self-delivery, the notes, the
   all-struck-off cleanup); `handle_deliver_message`; `sanitize_filename`;
   `file_mtime` / `set_file_mtime`; `load_state` / `save_state`.
2. Tests: `scripts/test-outbox-headers.sh`, `scripts/test-authoring-time.sh`,
   `scripts/test-edit-delivery.sh`.

## Related documents

- `docs/.templates/protocol.md`, `README.md`
- `#363`, `#101`, `#362`, `#374`, `#394`, `#315`, `#349`, `#306`
