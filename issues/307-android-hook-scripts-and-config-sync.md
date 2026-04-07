# Android hook scripts and config sync

## Overview

Android clients should have their own config file that syncs with the home
daemon (similar to how the contacts file syncs). Users can define hook scripts
and change settings from the phone. The phone has priority over the desktop
for this file (inverse of contacts where desktop has priority).

## Features

### Synced config file
- Separate from the desktop config — phone-specific settings
- Editable on both phone and desktop, phone wins on conflict
- Syncs same mechanism as contacts (hash comparison, push/pull)

### Hook scripts on Android
- Users write scripts from inside the rmail app
- Text editor for now, later: FSM diagram canvas or Scratch-style block
  programming
- Scripts react to rmail events (on_receive, on_send, on_update, etc.)

### App integration via periodics
- "Periodics" — scheduled checks that poll other apps/data sources
- Example: check calendar app every 30 minutes, send events to desktop
  via rmail message
- Self-scheduling: each periodic registers the next one
- Interface with gallery, calendar, other apps via content providers

### Inter-device automation
- Hook scripts can send rmail messages to trigger actions on other devices
- Desktop actions triggered by phone events and vice versa
- "Just write an rmail message" — the universal interface

## Status

Design phase. Depends on the hook system being stable on the daemon side.
