# Phase 2 Progress

Phase 2 focuses on shared device support, multi-device mailbox access, and codebase maintainability.

## Goals

- Enable laptops and secondary devices to sync with home daemon
- Implement attachments transfer file for shared device downloads
- Support outbox relay through home daemon
- Modularize codebase to avoid Lua upvalue limits

## Issues

| ID | Description | Status |
|----|-------------|--------|
| 200 | Shared device sync access | Will not implement |
| 201 | Modularize rmail.lua codebase | Open |
| 202 | Fix chunk response parsing | Fixed |
| 203 | LAN discovery improvements | Fixed |
| 204 | Fix partial send for large payloads | Fixed |
| 205 | Redirect service logs to /tmp | Fixed |

## Completed

- **202**: Fixed chunk response parsing - added status to http_post_batch results, fixed data access in send_next_chunks
- **203**: LAN discovery improvements - include LAN IP in payload, multicast + subnet scan fallback, NixOS path fixes
- **204**: Fixed partial send bug in http_encrypt_and_send - large payloads (attachment chunks) were getting truncated because send() wasn't looping. This was the root cause of "chunk failed" errors.
- **205**: Redirect service logs to /tmp (RAM-backed) - prevents startup messages from blocking TTY login prompt, avoids disk wear. Added view-logs.sh script and hidden .logs symlink.
- **200**: Will not implement - After design review, granular device permissions add too much complexity for unclear use cases. The laptop-at-library scenario can use the Android app. Daemon-to-daemon sync would require new code and raises unanswered questions about copy/move/mirror semantics.

## Notes

- Phase 2 originally aimed to enable shared device sync, but after design review this was deferred
- The remaining focus is codebase maintainability (issue 201)
- Laptop sync use case can be addressed with Android app for now
- Issue 201 addresses the Lua 60-upvalue limit by splitting into modules
