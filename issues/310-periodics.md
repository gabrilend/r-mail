# Periodics — scheduled app polling on Android

## Overview

"Periodics" are scheduled checks that poll other apps or data sources at
regular intervals. Each periodic registers the next one, creating a
self-scheduling chain — human-oriented threadpools for phone automation.

The core insight: most phone apps don't push data to rmail, so we poll them.
Check calendar every 30 minutes, send new events to desktop. Check gallery
for new photos, sync them somewhere. The phone becomes a sensor that feeds
data into the rmail network.

## Core concept: self-scheduling chains

Each periodic execution schedules the next one:

```
check_calendar()
  → find new events
  → send rmail message to desktop
  → schedule check_calendar() in 30 minutes
```

This creates a chain that runs indefinitely. The "willpower is in the design" —
you define how to react, then the system follows through automatically.

## Use cases

### Calendar → Desktop notifications
- Poll calendar app every N minutes
- Compare against last-known events (stored in periodic state)
- Send new/changed events to desktop via rmail
- Desktop hook displays notification or adds to local calendar

### Photo sync
- Poll gallery for new photos since last check
- Send as attachments to a designated recipient (could be self)
- Selective sync: only photos in certain albums, or matching criteria

### App state monitoring
- Check if certain apps are running
- Monitor battery level, storage space
- Send alerts when thresholds crossed

### Cross-device automation
- Phone detects you're home (wifi network)
- Sends rmail message to desktop
- Desktop hook runs "welcome home" script

## Data model

Periodic definition (stored in synced phone config, issue #308):

```
periodic:
  name: "calendar-sync"
  interval_minutes: 30
  source: "content://com.android.calendar/events"
  query: "dtstart > ?"  # events starting after last check
  action: "send_to_desktop"
  state:
    last_check: 1234567890
    last_event_ids: [...]
```

State is mutable — updated after each execution. Definition is immutable
(edited via script editor, issue #309).

## Android implementation considerations

### WorkManager vs AlarmManager
- WorkManager: Android's recommended job scheduler, handles doze mode
- AlarmManager: more precise timing but harder to use correctly
- WorkManager is probably right for "every 30 minutes" type tasks

### Content providers
- Calendar: `content://com.android.calendar/events`
- Contacts: `content://com.android.contacts/contacts`
- Media: `content://media/external/images/media`
- Each requires specific permissions

### Battery and resource constraints
- Android aggressively kills background work
- Need to respect doze mode and battery optimization
- User may need to whitelist rmail from battery optimization
- Minimum practical interval: probably 15 minutes

### Permissions
- Calendar: READ_CALENDAR
- Photos: READ_EXTERNAL_STORAGE or READ_MEDIA_IMAGES (Android 13+)
- Contacts: READ_CONTACTS
- Each periodic may require different permissions

## Unanswered questions

### Interval granularity
- What's the minimum useful interval? 1 minute? 5 minutes?
- Should intervals be fixed (every 30 min) or relative (30 min after last)?
- What about "at specific time" vs "every N minutes"?

### Failure handling
- What if a periodic fails? Retry immediately? Skip to next interval?
- Should failures be reported to user? To desktop?
- Max retries before giving up?

### State persistence
- Where does periodic state live? SQLite? SharedPreferences? File?
- What happens if state is corrupted? Reset and re-sync everything?
- Should state sync to desktop too? (So you can see what the phone "knows")

### Script complexity
- Are periodics just pre-defined patterns, or full scripts?
- If scripts: what language? Lua? Custom DSL? Visual blocks?
- How much can a periodic script do? Just read + send, or arbitrary actions?

### Interaction with hooks
- Periodics are like automated "incoming events"
- Should they trigger on_receive hooks on the desktop?
- Or a separate on_periodic hook?

## Dependencies

- Issue #308 (synced phone config) — periodic definitions stored there
- Issue #309 (script editor) — periodics are a type of script

## Related concepts

From the original mail:
> "Why would you ever share code? That stuff's all machine generated on demand."

Periodics are infrastructure for personal automation. Each user's setup is
unique — generated for their needs, not shared as a library. The system
provides the primitives (poll, compare, send), users compose them.

## Status

Design phase. Needs answers to the unanswered questions before implementation.

## Source

Mail: ~/mail/inbox/Android — file processed and removed
