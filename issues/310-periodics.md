# Periodics — scheduled app polling on Android

## Overview

"Periodics" are scheduled checks that poll other apps or data sources at
regular intervals. Each periodic registers the next one, creating a
self-scheduling chain. They only operate according to the sync cycle, so
they will do things like say "wait at least 5 minutes then do this thing"
and it will automatically have an decrementing script running each sync
cycle that decrements a persistent counter. When that counter reaches zero,
the function changes from the sync cycle decrement function/script to the
desired, scheduled function, followed by a resetting of the sync-cycle
counter (if repeat is specified) and a changing of the scheduled function
to the decrement function/script. Essentially just swapping a pointer
toward cached functions.

minimum timeframe and the timeframe increment is determined by the length
of the sync cycle. For this reason, sync cycle timing must be made
configurable by the user - different use-cases will need different timings,
and for each mailbox the config file can specify.

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
