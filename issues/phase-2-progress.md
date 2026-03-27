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
| 200 | Shared device sync access | Open |
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

## Notes

- Phase 2 builds on Phase 1's LAN discovery to enable devices on different networks
- Primary use case: laptop at library syncing with home daemon
- Enables true multi-device mailbox without each device needing port forwarding
- Issue 201 addresses the Lua 60-upvalue limit by splitting into modules
