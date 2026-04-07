# Synced phone config

## Overview

Android clients get their own config file that syncs with the home daemon,
similar to how the contacts file syncs. Users can change phone-specific
settings from either the phone or the desktop.

## Design

- Separate file from the desktop config — phone-specific settings only
- Editable on both phone and desktop, phone wins on conflict
- Syncs using the same mechanism as contacts (hash comparison, push/pull)
- Daemon stores it alongside the mailbox (e.g. `phone-config`)
- Android app reads/writes it via new API endpoints

## Status

Design phase.
