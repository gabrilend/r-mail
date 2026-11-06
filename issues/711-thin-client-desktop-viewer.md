# #711 — Thin client sync daemon for laptops

## Current Behavior

Built: a thin client in Lua that mirrors a home mailbox into a local
folder and syncs it through the phone API (#709), making
only outbound connections.  Its code is shared by every platform in
`clients/shared/` (`rmail-client.lua`, `protocol.lua`, `sync.lua`,
`store.lua`, `watcher.lua`); each platform folder holds an installer, a
`run` script and its file watcher: `clients/linux/` (inotify),
`clients/macos/` (`rmail_fswatch.c`), `clients/windows/`
(`rmail_fswatch_win.c`).  Their install scripts are named per platform
(#712).  The "Current state" below lists the earlier Linux-only layout.
Of the stretch goals, the terminal viewer is built (2026-11-05, see
Status); the rest are not started.


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
2. Built 2026-11-05: the terminal viewer, the read-only half of "Built-in
   TUI editor" below.
3. Remaining: the editor itself, and the other stretch goals, each its
   own issue when taken up.

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

## Status

The sync daemon is built (see Current Behavior).  Built 2026-11-05: a
terminal viewer, the "desktop viewer" of this issue's name, from the
read-only half of `clients/editor-design.md`.

- `clients/shared/renderer.lua` — the double-buffered cell grid: cells
  with tags, a flush that writes only changed cells and does not repeat
  a style within a run, wide characters as two cells, and the
  `update_tag` batch update the design left as a TODO.
- `clients/shared/wrap.lua` — UTF-8 characters, their screen widths
  (the emoji and East Asian wide ranges the design's open items asked
  for), and wrapping that keeps the writer's newlines apart from wrap
  points, so a resize only works the wrap points out again.
- `clients/shared/term.lua` — raw mode through `stty`, the size, and
  keys as names (both spellings of the arrow keys).
- `clients/shared/viewer.lua` and `rmail-view.lua` — the screen layout of
  the design (status bar, main area, hint bar) with its list and read
  modes; `clients/linux/view.sh` and `clients/macos/view.sh`.

Second slice built 2026-11-06 (branch `claude/711-edit-mode`, stacked on
`claude/711-terminal-viewer`): edit mode, with the arrow-key keybinds.

- `clients/shared/editbuf.lua` — the gap buffer of the design (the
  characters before the cursor and the ones after it, nearest last, so
  typing and deleting at the cursor is one push or pop), its screen rows
  worked out from the width at hand and never stored, the cursor's row
  and column, moving between rows at a kept column, a line cut with its
  newline, and undo by snapshots, a run of typing or deleting as one step.
- `clients/shared/viewer.lua` — `n` starts a new message in the outbox
  (in the contact folder shown, #214, or at its top), `e` opens an
  outbox file from the list or while reading it.  Keys: typing, Enter,
  Tab (four spaces), Backspace, Delete, the arrows, Home/End (the
  writer's line), Page Up/Down, Ctrl-S save, Ctrl-X exit, Ctrl-K cut a
  line (repeated cuts gather), Ctrl-U paste, Ctrl-Z undo.  The terminal's
  cursor is shown where the text's is, and hidden outside edit mode.
- `clients/shared/term.lua` — every control key comes out as `ctrl-` and
  its letter.
- Test: `scripts/test-thin-client-editor.sh` (a pretend terminal, as the
  viewer's own test).

Not built: the vim keybinds, Ctrl-F search, the system clipboard (an
internal yank buffer stands in, which the design allows), contacts mode,
mouse, the snippet drawer, Windows, and the web client.

## Decisions (2026-11-06)

Made while building edit mode, to be overturned by the owner's word:

- **Only outbox files are edited.**  The inbox holds what arrived; an
  edit there would look like the sender's words.  `e` does nothing in
  the inbox, and a new message always goes in the outbox.
- **A save writes the whole file at once**, beside it under a hidden name
  and then moved over it.  The daemon skips hidden files and reads a
  message when it changes, so it never reads half of one.
- **A file that changed on disk since it was opened is not saved over
  without a second Ctrl-S.**  The daemon writes to outbox files (a mark
  such as `CANNOT REACH`, a link's `URL:` line), and saving over such a
  change silently would drop it.
- **A new message never takes a name already in its folder**, nor one
  with `/` or a leading dot: the first would write over another message,
  the others would put it somewhere else or hide it from the daemon.
- **A new message starts as `to: ` and a blank line**, the cursor where
  the recipient goes, since every outbox file needs a recipient.
- **Arrow keys first; vim later.**  The design names arrows the default
  scheme; the vim scheme needs a mode line and its own tests, and is the
  next slice.
- **Undo by snapshots of the text**, not by replaying edits: a message is
  small, a copy per step costs little, and a snapshot cannot be replayed
  wrongly.  At most 200 steps.
- **Tab inserts four spaces**, as `wrap.lua` already shows a tab, so what
  is written is what was seen.
- **An internal yank buffer**, the design's own fallback, rather than
  `xclip`/`pbcopy`: it needs nothing installed and behaves the same on
  every machine; the system clipboard is left for when it is asked for.

## Decisions (2026-11-05)

- **A terminal program, not a page.**  The issue's own stretch goal for
  a viewer on the computer is the built-in TUI of `editor-design.md`,
  which is Lua with escape sequences and no curses; the web client in
  this issue is for any device and is #714's ground now.
- **Read-only first.**  The viewer reads `inbox/` and `outbox/` and
  writes nothing, so it cannot fight the sync client over a file, and
  "the user reads and writes files with whatever tools they already
  use" still holds for writing.  Edit mode is the next slice.
- **`stty`, not `rmail_term.c`.**  The design puts raw mode in a small C
  module; `stty` does the same on Linux and macOS with nothing to
  compile, which matters for a client that installs by copying.  The
  cost is that plain Lua cannot catch SIGWINCH, so the size is measured
  again before each frame and a resize shows at the next key (Ctrl-L
  redraws).  When edit mode needs keys faster than a shell call per
  escape sequence allows, `rmail_term.c` is still the plan.
- **Any mailbox folder.**  It reads a thin client's mirror or a daemon's
  own mailbox alike, since both have `inbox/` and `outbox/`.  With no
  argument it uses the one `~/mail-remote/mailbox-*`, and asks for a
  folder when there are none or several.
- **Newest first, hidden files left out, folders opened in place.**
  Contact folders and other subfolders are browsed rather than skipped;
  hidden files are the daemon's and client's bookkeeping.
- **Header lines are styled** — the lines before a message's first blank
  line, when they start like `field:` — so the body stands apart.
- **A binary file is described, not shown**: a zero byte in its first
  4 KB.
- **Both key schemes at once** for movement (arrows and `h`/`j`/`k`/`l`),
  since with nothing to type in read-only mode they cannot clash; the
  design's choice between schemes belongs to edit mode.
- **Windows is not offered** yet: it has no `stty`, and its console
  needs the `SetConsoleMode` route the design describes.
- Test: `scripts/test-thin-client-viewer.sh`.
