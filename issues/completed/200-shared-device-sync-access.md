# 200 - Shared Device Sync Access

## Current Behavior

rmail currently supports two device roles:
1. **Home daemon** (`owned = true`) - the always-reachable server that receives messages
2. **Android client** - syncs inbox/outbox with home daemon via the rmail-android app

There is no intermediate option for secondary devices (laptops, other computers) to share a mailbox with the home daemon. A laptop at a library cannot receive messages directly (library doesn't port-forward) and has no way to sync with the home daemon.

## Intended Behavior

Add granular config flags to enable shared device access:

```ini
# Instead of just "owned = true", use:
inbox_access = true      # sync inbox from home daemon
outbox_access = true     # send messages via home daemon
attachments_access = true  # sync attachments from home daemon
```

This enables:
- Laptops to sync inbox while traveling (via home daemon)
- Multiple devices sharing the same mailbox
- Fine-grained control over what syncs where

## Attachments Transfer File

For devices with `attachments_access = true`, implement a transfer-style file that shows available attachments on the home daemon:

```
  name               delete X to download locally
  --------------------------------------------------------------------------------
  vacation-photo.jpg X
  work-document.pdf  X
  music.mp3          X
  --------------------------------------------------------------------------------
```

### Behavior

1. **X column**: Blocker that prevents download to this device
2. **Delete the X**: Triggers file transfer from home daemon to local device
3. **Replace X during transfer**: Cancels transfer, deletes partial file
4. **Disk space check**: If disk is full, show "ran out of disk space" instead of X
5. **Already have file**: Leave X column empty (no indicator needed)

### Design Notes

- Files don't have to be from contacts - user can manually add files to attachments directory
- Column positioning: `longest_filename_length - filename_length` spaces between filename and X
- Consent for incoming attachments: pulled from home daemon, not original sender
- When any device accepts an attachment, home daemon handles the transfer
- Consent files cleaned up when transfer completes to home daemon

## Implementation Steps

### Phase 1: Config Flags

1. Add `inbox_access`, `outbox_access`, `attachments_access` config parsing
2. Default behavior: if `owned = true` and none of these are set, assume all access
3. Validate: at least one access flag must be set for non-owned devices

### Phase 2: Inbox Sync for Shared Devices

1. Shared device periodically syncs inbox from home daemon
2. Home daemon must expose an inbox listing endpoint
3. Messages sync like Android client sync
4. Deleted messages: propagate deletion to all shared devices

### Phase 3: Outbox Relay

1. Shared device with `outbox_access` can compose messages locally
2. Outbox files sync to home daemon
3. Home daemon handles actual delivery
4. Status updates sync back to shared device

### Phase 4: Attachments Transfer File

1. Home daemon exposes attachment listing endpoint
2. Shared device writes ~/mail/attachments-available file
3. Implement X-column deletion detection
4. Handle file transfer from home daemon to shared device
5. Disk space checking before transfer
6. Progress indication during transfer

## Edge Cases

1. **Multiple devices accept same attachment**: First one to finish wins, others see empty X
2. **Device goes offline during transfer**: Resume on reconnect (chunk-based like current attachments)
3. **Home daemon restarts**: Transfers resume (state persisted)
4. **Conflict detection**: What if two devices modify same outbox file?

## Related Files

- `rmail.lua`: Config parsing, sync functions
- `~/mail/transfers`: Existing outgoing transfer progress (different from this feature)
- Android client: Similar sync patterns

## Notes

- This feature was discussed in the context of laptops connecting from libraries/public wifi
- The library scenario: can send (outbound works) but cannot receive directly
- Home daemon acts as the always-reachable relay
- Different from Android sync - this is for full desktop/laptop rmail instances

## Related Conversation

User noted that for attachments on shared computers:
> "Maybe there's a consent file pushed to each computer with a shared attachments inbox? But pulled from the home daemon instead of the peer who sent it originally..."

This is addressed in the attachments transfer file design - shared devices pull from home daemon, which handles consent with original sender.

## Permission Combinations Grid

| Inbox | Outbox | Attach | Use Case | Notes |
|:-----:|:------:|:------:|----------|-------|
| ❌ | ❌ | ❌ | (invalid) | Must have at least one permission |
| ✅ | ❌ | ❌ | Read-only inbox | Check messages but can't reply. Good for shared/public display. |
| ❌ | ✅ | ❌ | Send-only | Compose and send but can't see inbox. Weird but valid — blind outbox. |
| ❌ | ❌ | ✅ | Attachments-only | Download files but not messages. File transfer station. |
| ✅ | ✅ | ❌ | Full messaging, no files | Normal email without large file transfers. Bandwidth-limited devices. |
| ✅ | ❌ | ✅ | Receive everything | Read messages and attachments but can't send. Archive/backup device. |
| ❌ | ✅ | ✅ | Send with files, no inbox | Can send attachments but never sees replies. Upload station? |
| ✅ | ✅ | ✅ | Full data access | Equivalent to current Android behavior (minus contacts write). |

### Outbox without Attachments

Device can compose messages with text but attachment buttons are disabled/hidden.
If a message in outbox references an attachment, the attachment won't sync — home
daemon relays the text but skips the attachment, OR returns an error on sync
asking user to remove attachment from message.

### Attachments without Outbox

Device can download attachments from inbox but cannot send attachments to others.
The `attachments-available` transfer file works normally for receiving.
Compose screen attachment button is disabled.

### Without Inbox Access

Device can send (outbox syncs to home daemon) but never sees replies.
Sync response includes: `"inbox": null` or `"inbox_access": false`.
UI shows warning: "Inbox sync disabled — replies won't appear on this device."

---

## Contacts File Access

**Problem:** If a device can write to contacts, it can:
1. Change its own permissions (escalate to full access)
2. Change other contacts' tokens/IPs (redirect or impersonate)
3. Add rogue contacts

**Proposed model:**
- `own = true` = full trusted device (contacts read/write, config access, implies all data access unless explicit flags set)
- Granular flags without `own = true` = partial trust, **contacts read-only**

This means:
- Android with `own = true` keeps current behavior (backwards compatible)
- Laptop with just `inbox_access = true` can read contacts for reference but not modify
- Sync response includes contacts for display but POST /api/contacts returns 403

**Alternative:** Separate `contacts_write = true` flag. But this adds complexity and the
use case for "data access + contacts write but not own" is unclear.

---

## Sync Response with Permissions

When syncing, include permission status so client can show appropriate warnings:

```json
{
  "inbox": [...],
  "outbox": [...],
  "attachments": [...],
  "contacts": "...",
  "permissions": {
    "inbox": true,
    "outbox": false,
    "attachments": true,
    "contacts_write": false
  }
}
```

Client shows persistent warning banners for disabled permissions:
- "Outbox sync disabled — messages sent here won't be delivered"
- "Inbox sync disabled — new messages won't appear on this device"
- "Attachments disabled — files won't sync to this device"
- "Contacts read-only — edit on home device to make changes"

---

## Original Motivation

From discussion: the use case that prompted this feature was **laptops connecting
from libraries/public WiFi**. The library doesn't port-forward, so the laptop can't
receive messages directly. It needs to sync with the home daemon.

But maybe you don't fully trust the laptop (could be stolen, used on public network,
shared with family). Granular permissions let you:
- Give read-only access to a shared family computer
- Let a travel laptop send/receive but not modify contacts
- Create a "file download station" that only syncs attachments

---

## Documentation Updates Needed

When implementing this feature, update these docs:

| File | Section | Changes |
|------|---------|---------|
| `docs/android-instructions.md` | Vocabulary, Prerequisites, `own = true` setup | Add note about granular alternatives, explain that `own = true` remains valid |
| `docs/android-instructions.md` | Troubleshooting "Is `own = true` set?" | Mention granular flags as alternative |
| `docs/protocol.md` | "Own-device only" endpoints section | Split by permission level, document which endpoints need which permission |
| `docs/service.md` | (new section) | Add "Shared device configuration" explaining granular access |
| `README.md` | If it mentions `own = true` | Brief note about granular options |

---

## Design Review Discussion (2026-03-26)

After extensive discussion, this feature was deferred. Key insights:

### The `own = true` behavior today

Putting `own = true` on another daemon's contact entry grants them `/api/` access,
but **does not trigger automatic sync**. The daemon's sync loop only sends outbox
messages — it doesn't pull from other daemons. Two daemons with mutual `own = true`
are just two independent mailboxes that trust each other.

For the laptop-at-library use case, the laptop daemon would need NEW code to
actively sync FROM the home daemon. This doesn't exist yet.

### Design questions that remain unanswered

1. If laptop syncs from home, what happens to messages? Copy? Move? Mirror?
2. If both daemons receive directly (both port-forwarded), do inboxes merge?
3. What about conflicts when two devices modify the same outbox file?

### Complexity concerns

The granular permissions (`inbox_access`, `outbox_access`, `attachments_access`)
spiraled into:
- Permission matrices with 8 combinations
- Config/contacts access control questions
- Multi-mailbox interconnection as a "platform"
- Automation use cases

This is a lot of conceptual surface area. The original problem (laptop at library)
might not justify this complexity.

### The simpler alternative

For automation between mailboxes or file transfers, just use the filesystem:

```sh
cp ~/mailbox-a/attachments/photo.jpg ~/mailbox-b/inbox/
```

The filesystem IS the API. No new permission concepts needed.

### Why not implement now

1. **Use case unclear**: The laptop-at-library scenario can be solved by the
   Android app or by waiting until you're home
2. **Complexity creep**: Granular permissions add many edge cases
3. **Sharp edge**: rmail's value is simplicity. `own = true` is all-or-nothing,
   which is easy to understand
4. **Automation alternative**: Scripts can manipulate files directly without
   needing API permissions

### If revisited later

The core missing piece is: daemon-to-daemon sync. If that becomes necessary:
1. Add code for daemon to actively pull from another daemon with `own = true`
2. Decide on copy vs move vs mirror semantics
3. Consider whether granular permissions are worth the complexity

---

## Status

**WILL NOT IMPLEMENT** - Deferred. Complexity outweighs benefit for current use cases.
Can be reopened if daemon-to-daemon sync becomes a clear need.
