# Synced phone config

## Overview

Android clients get their own config file that syncs with the home daemon,
similar to how the contacts file syncs. Users can change phone-specific
settings from either the phone or the desktop.

This is the foundation for the Android automation stack — scripts (#309)
and periodics (#310) both live here.

## Why a separate config?

The desktop config (rmail.lua's config) contains daemon settings: ports,
paths, hook scripts, encryption keys. Most of these don't make sense on
the phone.

The phone config contains:
- Phone-specific UI settings (notification preferences, theme)
- Hook scripts that run ON THE PHONE (not the daemon)
- Periodic definitions (calendar sync, photo backup schedules)
- Phone-to-daemon relationship settings

Keeping them separate avoids confusion and prevents phone settings from
accidentally breaking the daemon.

## Data model

```
phone-config:
  # Identity
  device_name: "pixel-7"
  device_id: "abc123..."  # generated on first sync

  # UI preferences
  notifications:
    enabled: true
    sound: "default"
    vibrate: true
  theme: "system"  # light, dark, system

  # Hook scripts (run on phone)
  hooks:
    on_receive: |
      -- lua script that runs when phone receives a message
      if sender == "mom" then
        notify_urgent()
      end
    on_send: null
    on_sync_complete: null

  # Periodics (scheduled tasks)
  periodics:
    - name: "calendar-sync"
      interval_minutes: 30
      enabled: true
      script: |
        -- check calendar, send new events to desktop
      state:
        last_check: 1234567890

  # Sync metadata
  last_modified: 1234567890
  last_synced: 1234567890
```

## Sync mechanism

Reuse the contacts sync pattern:

1. **Hash comparison**: Phone and daemon each compute hash of their version
2. **Conflict resolution**: Phone wins (user is actively editing on phone)
3. **Push/pull**:
   - Phone changed → push to daemon
   - Daemon changed → pull to phone
   - Both changed → phone wins, daemon version discarded

### New API endpoints

```
GET  /phone-config         → returns current config + hash
POST /phone-config         → upload new config (phone → daemon)
GET  /phone-config/hash    → just the hash (for quick comparison)
```

### Sync flow

```
Phone sync cycle:
  1. GET /phone-config/hash
  2. Compare with local hash
  3. If different:
     a. If local is newer → POST /phone-config
     b. If remote is newer → GET /phone-config, save locally
     c. If both changed → POST local (phone wins)
```

## Desktop editing

Users can edit phone config from desktop by:
1. Editing the file directly: `~/mail/phone-config` (or wherever daemon stores it)
2. Changes sync to phone on next sync cycle

This enables:
- Writing complex scripts in a real text editor
- Bulk editing periodic definitions
- Backup/restore via normal file operations

## Conflict scenarios

### Scenario A: User edits on desktop while phone is offline
1. Desktop edits `phone-config`, saves
2. Phone comes online, syncs
3. Phone sees remote is newer, pulls changes
4. Done — desktop edits applied

### Scenario B: User edits on both simultaneously
1. Desktop edits config
2. Phone edits config (different section)
3. Phone syncs, sees conflict
4. Phone wins — desktop changes lost
5. User should see warning? Or just accept phone-wins rule?

### Scenario C: Phone offline for days, then syncs
1. Desktop has been edited multiple times
2. Phone has local changes
3. Phone syncs — phone version overwrites all desktop changes
4. This might be surprising — consider showing "you're about to overwrite
   N days of desktop changes, continue?"

## Storage locations

**On daemon:**
- `~/mail/phone-config` (or configurable path)
- One file per device? Or one file with sections per device?
- Single file simpler to start

**On phone:**
- Internal storage, private to app
- SharedPreferences for simple values, file for complex (scripts)
- Or just JSON file for everything

## Security considerations

- Config may contain hook scripts — code that runs on the phone
- Daemon-edited scripts run on phone — trust model?
- For now: assume user controls both, no sandboxing
- Future: script signing? Capability restrictions?

## Unanswered questions

### Multi-device support
- What if user has two phones?
- Separate config per device? Merged config?
- Device ID distinguishes them, but how does daemon store multiple?

### Schema versioning
- What if phone app updates and config format changes?
- Need migration strategy — version field in config?

### Partial sync
- Sync entire config, or just changed sections?
- Full sync simpler, but wasteful for large script libraries
- Start with full sync, optimize later if needed

### Hook script format
- Lua? (matches desktop)
- Something simpler? (phone might not have Lua runtime)
- Or just shell-ish commands?

### Default config
- What ships with a fresh install?
- Empty? Sensible defaults? Example scripts?

## Implementation steps

1. Add phone-config file to daemon storage
2. Implement GET/POST /phone-config endpoints
3. Add hash computation and comparison
4. Android: local storage for phone-config
5. Android: sync logic in existing sync cycle
6. Android: UI to view/edit settings
7. Android: hook script execution (depends on #309)
8. Android: periodic execution (depends on #310)

## Dependencies

- None — this is foundational for #309 and #310

## Dependents

- Issue #309 (script editor) — scripts stored here
- Issue #310 (periodics) — periodic definitions stored here

## Status

Design phase.

## Source

Mail: ~/mail/inbox/Android — file processed and removed
