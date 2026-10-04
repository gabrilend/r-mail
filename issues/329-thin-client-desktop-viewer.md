# #329 — Thin client sync daemon for laptops

## Current Behavior

Built: a thin client in Lua that mirrors a home mailbox into a local
folder and syncs it through the phone API (#new-the-phone-api), making
only outbound connections.  Its code is shared by every platform in
`clients/shared/` (`rmail-client.lua`, `protocol.lua`, `sync.lua`,
`store.lua`, `watcher.lua`); each platform folder holds an installer, a
`run` script and its file watcher: `clients/linux/` (inotify),
`clients/macos/` (`rmail_fswatch.c`), `clients/windows/`
(`rmail_fswatch_win.c`).  Their install scripts are named per platform
(#351).  The "Current state" below lists the earlier Linux-only layout.
The stretch goals are not started.


## Problem

Laptops are unreliable as rmail hosts. When you leave home, your public IP
changes, port forwarding breaks, and your daemon becomes unreachable. The IP
recovery mechanisms exist but aren't guaranteed — they depend on recipients
being online at the right time.

Running a full daemon on a laptop means your mailbox only works reliably
when you're at the location where you set it up. Take your laptop to a
coffee shop and you're cut off from incoming messages until the recovery
handshake succeeds (if it does).

## Intended Behavior

A sync daemon that mirrors a local mailbox directory from a home rmail
daemon. Same file-based philosophy as rmail itself — the user reads and
writes files with whatever tools they already use (vim, nano, VS Code,
cat, etc).

The thin client:
- Syncs `~/mail-remote/` with the home daemon over AES-256-GCM TCP
- Watches the local outbox and contacts via inotify — changes sync
  immediately, no manual trigger needed
- Falls back to interval-based sync for incoming messages
- Does NOT run its own mail server, accept connections, or need port
  forwarding

User workflow:
1. `rmail-client` runs in the background, syncing the local mailbox
2. Inbox messages appear in `~/mail-remote/inbox/` — read with any tool
3. Write a file to `~/mail-remote/outbox/` — it syncs home and delivers
4. Edit `~/mail-remote/contacts` — changes sync back to the daemon

This works anywhere with internet access, because the client only makes
outbound connections to the known home IP.

## Architecture

Written in Lua, reuses the daemon's libraries directly:
- `rmail_crypto.so` — AES-256-GCM encryption
- `rmail_inotify.so` — outbox/contacts file watching
- `luasocket` — TCP networking
- `dkjson` — JSON encoding

The client is ~200 lines of Lua. It uses the same `select()` + inotify
pattern as the daemon's main loop: sleeps until a file changes or the
sync interval expires.

## Current state

Implemented in `clients/linux/`:
- `rmail-client.lua` — entry point (sync daemon)
- `lib/protocol.lua` — wire protocol client (all API endpoints)
- `lib/sync.lua` — sync cycle (mirrors Android SyncManager)
- `lib/store.lua` — local mailbox state management

## Suggested Implementation Steps

1. Built: `clients/shared/*.lua`, the three platform folders.  The guide
   is `docs/.templates/thin-client.md`.
2. Remaining: the stretch goals below, each its own issue when taken up.

## Stretch goals

### Web client
Served by the home daemon — add a `/web/` endpoint that serves HTML/JS.
WebCrypto API handles AES-256-GCM in browser. Works on any device.

### macOS / Windows
The Lua client should work on macOS as-is (POSIX). Windows would need
a different inotify mechanism (ReadDirectoryChangesW) or interval-only
sync.

### Built-in TUI editor
See `clients/editor-design.md` for the full spec. Double-buffered cell
grid, dynamic reflow, tag system, vim/arrow keybinds. Not needed for v1
since users can use any editor, but could be added later for a more
integrated experience.
