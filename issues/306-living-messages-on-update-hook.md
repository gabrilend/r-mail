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
- $2: subject
- $3: old message body (the current inbox file content)
- $4: new message body (what the sender changed it to)

stdout: replaces the saved body (like on_receive_raw)

If no on_update hook is configured, the update is applied directly.

Use cases:
- Diff notification: hook writes a diff summary to a log
- Reject updates: hook outputs the old body unchanged
- Transform: hook modifies the update (e.g., append "EDITED" marker)

## Helper script

`scripts/checksum-message.sh <filepath>` — outputs SHA-256 of a message
file. Meant to be called from hook scripts to detect changes.

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

## Status

Not yet implementing.
