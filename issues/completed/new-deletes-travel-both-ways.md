# #new-deletes-travel-both-ways — Deleting a message, on either side, is told to the other

## Status

Completed — a blueprint written 2026-10-04 (#402) for what was built
before issue files described it.

## Current Behavior

A message exists in two places — the author's outbox file and each
recipient's inbox file — and deleting either is news for the other.  All
three ways travel as `POST /delete {message_id}`, retried each cycle
until answered (a 404, "already gone", counts as answered):

| who deletes what | sent to | what the other side does |
|---|---|---|
| the author deletes the outbox file | every recipient | deletes the inbox copy, runs `on_delete`, drops any consent form or arriving pieces for that message; the outbox record goes once every recipient has answered |
| the author removes one `to:` line | that recipient | the same, for them alone; their record goes when they answer |
| a recipient deletes the inbox file | the author | runs `on_delete`, strikes that recipient's `to:` line from the outbox file, drops transfers to them; when no recipient is left the outbox file is deleted |

On the recipient's side the deletion is marked pending in the inbox
record the first time it is seen (and `on_delete` runs once), then
retried until the author answers.  A sender unknown here is not told.
A message to oneself is deleted on the other side directly.

**Attachments are not deleted** with the message they came with: they
are the owner's files (#355).

**Races** (#323): an edit arriving for a message the recipient has just
deleted is answered 404, and the author treats that as the deletion —
the copy is never re-created.

## Intended Behavior

As above.

## Suggested Implementation Steps

1. `rmail.lua`: `sync_outbox` (`notify_deletion`, `notify_removal`, the
   cleanup of deleted files once all are told), `sync_inbox` (the
   pending-delete marks and their notices), `handle_delete` (both
   directions), `remove_recipient_from_file`, `self_delete_from_inbox`,
   `self_delete_from_outbox`.
2. Tests: `scripts/test-authoring-time.sh` runs edits and deletes between
   two mailboxes; the race matrix is in #323.

## Related documents

- `#323`, `#355`, `#new-a-message-is-a-file`, `#407` (a cancelled
  attachment is not a deleted message)
