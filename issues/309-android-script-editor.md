# In-app script editor for Android

## Overview

Users write hook scripts from inside the rmail app. Scripts react to rmail
events (on_receive, on_send, on_update, etc.) and can interface with other
apps on the phone.

## Design

- Text editor for now
- Later: FSM diagram canvas or Scratch-style block programming
- Scripts stored in the synced phone config (issue #308)
- Can trigger actions on other devices by sending rmail messages
- Inter-device automation: desktop actions triggered by phone events and
  vice versa — "just write an rmail message" as the universal interface

## Dependencies

- Issue #308 (synced phone config) — scripts need somewhere to live
- Daemon hook system should be stable first

## Status

Design phase.
