# Periodics — scheduled app polling on Android

## Overview

"Periodics" are scheduled checks that poll other apps or data sources at
regular intervals. Each periodic registers the next one, creating a
self-scheduling chain.

## Design

- Example: check calendar app every 30 minutes, send events to desktop
  via rmail message
- Self-scheduling: each periodic registers the next check
- Interface with gallery, calendar, other apps via Android content providers
- Can send rmail messages to trigger desktop actions
- Configuration lives in the synced phone config (issue #308)

## Dependencies

- Issue #308 (synced phone config) — periodic definitions stored there
- Issue #309 (script editor) — periodics are a type of script

## Status

Design phase.
