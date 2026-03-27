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

## Status

**OPEN** - Phase 2 feature
