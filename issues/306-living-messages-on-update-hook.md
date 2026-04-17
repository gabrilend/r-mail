# Living messages: outbox edits propagate to recipients

## Overview

All messages are "living" — editing an outbox file updates the recipient's
inbox copy. The outbox file is the source of truth.

## Detection

Each sync cycle, compute SHA-256 of each outbox file body and compare
against the checksum stored in outbox.json state. If different, the
message was edited since last sync.

Store in outbox.json:
```
state[filename].body_checksum = "abc123..."
```

## Propagation

When an edit is detected, send `POST /deliver` to each recipient with:
```json
{
    "type": "update",
    "message_id": "existing-uuid",
    "subject": "filename",
    "body": "new body content"
}
```

The receiver matches by message_id and overwrites the inbox file.

## on_update hook

New hook: `on_update` — runs synchronously before the updated body is
written to the inbox file.

Arguments:
- $1: sender name
- $2: absolute path to the saved inbox file (filename = subject, content = old body)
- $3: new message body (what the sender changed it to)

stdout: replaces the saved body (like on_receive_raw)

If no on_update hook is configured, the update is applied directly.

Use cases:
- Diff notification: hook writes a diff summary to a log
- Reject updates: hook outputs the old body unchanged
- Transform: hook modifies the update (e.g., append "EDITED" marker)

## Helper script

`helpers/checksum.sh <filepath>` — outputs SHA-256 of any file.
`helpers/filename.sh <filepath>` — extracts filename from a path.
Both meant to be called from hook scripts.

```sh
#!/bin/sh
sha256sum "$1" | cut -d' ' -f1
```

## Edge cases

- User does `:w` mid-edit: partial save gets sent. This is fine — the next
  save sends another update. Recipients always see the latest version.
- Multiple recipients: update sent to all, independently. Each recipient's
  on_update hook runs independently.
- Recipient deleted the message: update gets a 404, sender's state is
  cleaned up (recipient removed from outbox.json).
- Sender removes a to: line: existing deletion logic handles it (separate
  from update).

## Sender namespacing (refinement needed)

Currently, living messages are matched by message_id (UUID). But what happens
when two different senders both send a living message with the same subject?

Example:
- Alice sends "status" to Bob (living message, uuid-1)
- Carol sends "status" to Bob (living message, uuid-2)
- Bob's inbox has two files... both named "status"?

Current behavior: The second delivery would fail or overwrite, depending on
how filename conflicts are handled (see issue #312).

Proposed refinement: Ensure each living message is tied to one sender
specifically. Options:

1. **Namespace by sender**: Store as `alice/status` and `carol/status`
   - Changes inbox structure (directories per sender)
   - Clean separation, no conflicts possible

2. **Append sender to filename**: Store as `status-from-alice`, `status-from-carol`
   - Flat structure preserved
   - Uglier filenames

3. **Reject second sender**: If "status" exists from Alice, Carol's "status"
   is rejected as a conflict
   - Simplest, but might surprise users
   - First-come-first-served on subject names

4. **Use message_id only**: Ignore subject for matching, only use UUID
   - Current implementation does this for updates
   - But initial delivery still uses subject as filename

This needs a design decision before the edge case bites someone.

Source: ~/mail/inbox/rmail-improvements-too (reconstructed in notes/)

## Status

Implemented. All changes in rmail.lua.
