# Shared Text Editor Design

The editor is shared across the Linux, Windows, and Mac thin clients (not web).
Written in Lua using direct terminal escape sequences. No curses dependency.

---

## Bootstrap

Each client ships as a single `install.sh` script. The script:

1. Asks the user for home daemon host, port, and device token (interactive
   prompts, skippable via `--host`, `--port`, `--token` flags)
2. Connects to the daemon using the same AES-256-GCM wire protocol
3. Fetches the client source code via an API endpoint, delivered as an
   encrypted rmail package
4. Builds all C dependencies from source (Lua, luasocket, rmail_crypto,
   rmail_term, etc.)
5. Result: a fully self-contained client directory, ready to run

The client needs nothing pre-installed beyond a C compiler and a shell.
Everything else is built locally.

### Crypto bootstrap problem

The install script needs to decrypt the package it receives, but the
decryption library is inside that package. Options to resolve:

- Ship a minimal AES-256-GCM decryptor in the install script itself
  (OpenSSL CLI: `openssl enc -aes-256-gcm` can decrypt if we pass the
  key and nonce). Most systems have OpenSSL installed.
- Have the daemon serve an unencrypted bootstrap payload on a special
  one-time endpoint, authenticated by token in the URL. Less elegant
  but simpler.
- Bundle a tiny C decryptor in the install script as a here-document,
  compile it first, use it to decrypt the rest.

[TODO: decide which approach. OpenSSL CLI is the most pragmatic for v1.]

---

## Terminal setup

On startup:

1. Query terminal size (rows, columns). Use ANSI `\e[18t` or `stty size`.
2. Register a handler for `SIGWINCH` (terminal resize) to update dimensions
   dynamically. On resize, reflow all text (see Line wrapping below).
3. Enter raw mode (disable line buffering and echo) so we get individual
   keypresses.
4. Enable mouse reporting via `\e[?1000h` (basic) or `\e[?1006h` (SGR
   extended, better for wide terminals).
5. On exit, restore terminal state (cooked mode, mouse reporting off,
   show cursor).

Width and height are stored as character counts. All layout math uses
these values. The user can configure a default terminal size in the
config file — this determines the initial window dimensions.

---

## Rendering: double-buffered cell grid

### Cell structure

Each cell stores the character, its ANSI escape codes, and an arbitrary
tag set:

```lua
cell = {
    char     = "a",           -- the character (or "" for wide char continuation)
    ansi_on  = "\27[32m",     -- escape code to activate this cell's style
    ansi_off = "\27[0m",      -- escape code to deactivate
    tags     = {},            -- arbitrary tags (see Tag system below)
}
```

Storing ANSI codes directly (not semantic fg/bg/style) keeps the
rendering math simple — string comparisons and the collapsing
arithmetic work without a translation step.

Wide characters (CJK, emoji) occupy two cells. The first cell holds the
character; the second holds `{char=""}` as a continuation marker.
The renderer skips continuation cells.

### Tag system

Each cell carries a `tags` table — a set of string keys mapping to
arbitrary values. Tags let higher-level UI components (text boxes,
highlighted regions, selection ranges) claim ownership of cells without
tracking positions.

```lua
cell.tags = {
    ["textbox-compose"] = true,    -- this cell belongs to the compose box
    ["selection"]       = true,    -- this cell is currently selected
    ["header-field"]    = "to",    -- this cell is part of the "to:" header
}
```

UI components find their cells by tag, not by row/col. When the terminal
resizes and cells move, the tags travel with them. A component that needs
to update (e.g. change the color of all cells tagged "selection") iterates
the buffer looking for its tag, rather than remembering coordinates.

This decouples layout from identity: a text box doesn't need to know
where it is on screen, only what its tag is. Resize, reflow, and scroll
can move cells freely — the tags stay attached.

[TODO: implement tag-based batch update. E.g. `buffer:update_tag("selection",
{ansi_on = "\27[7m"})` to reverse-video all selected cells in one call.
Architecture is in place — cells have the tags field — but the query/update
API is not yet built.]

### Double buffer

Two buffers: `front` (what's on screen) and `back` (what we're building).

```lua
front[row][col] = cell
back[row][col]  = cell
```

**Important:** the back buffer is NOT cleared each frame. Cells persist
across frames, preserving their tags. UI code modifies cells in place
when state changes, rather than rebuilding from scratch. This means:

- Tags survive across frames without being re-attached
- Components that didn't change don't need to redraw
- Only cells that actually changed get new values written

The rendering cycle:

1. **Update** — UI code modifies cells in `back` buffer in response to
   input events. Only touched cells change.
2. **Diff** — compare `back` against `front`. Only emit ANSI for cells
   where `char`, `ansi_on`, or `ansi_off` differ.
3. **Flush** — write the diff to stdout in one `io.write()` call
   (minimize syscalls and flicker).
4. **Swap** — copy changed cells from `back` into `front`.

On terminal resize, both buffers are reallocated to the new dimensions
and the full screen is redrawn.

### ANSI output: branchless escape code collapsing

When emitting a row of changed cells, we collapse redundant escape
codes. Each cell's `ansi_on` is self-contained (idempotent), but
adjacent cells with the same `ansi_on` can share the escape sequence.

The collapsing uses arithmetic instead of branching:

```lua
-- Walking left to right across a row:
-- A = (prev_ansi_on == cur_ansi_on) and 1 or 0
-- B = "" (no-op string)
-- C = cur_ansi_on (the escape code)
-- emit = A * B + (1 - A) * C

-- In Lua with a string lookup table indexed 0/1:
local codes = { [0] = cur_ansi_on, [1] = "" }
local emit = codes[same_as_prev]
```

For a row of 4 green characters:
- Cell 1: emit `\27[32m`, emit `a`
- Cell 2-4: prev matches, emit char only
- After cell 4 (or when next cell differs): emit `\27[0m`

At the end of each row, reset all attributes.

---

## Screen layout

```
+--------------------------------------------------+
| mailbox-name           [synced 2m ago] [S]ync    |  <- status bar
+--------------------------------------------------+
|                                                    |
|  (main area: inbox list, message view, or editor) |
|                                                    |
+--------------------------------------------------+
| ^S Save  ^X Exit  ^F Find  ^K Cut  ^U Paste     |  <- hint bar
+--------------------------------------------------+
```

- **Status bar** (row 0): mailbox name, sync status, connection indicator.
- **Main area** (rows 1 to height-2): the active view.
- **Hint bar** (row height-1): context-sensitive keybind hints.

The main area switches between modes:
- **List mode** — inbox/outbox file list
- **Read mode** — viewing a message (read-only, scrollable)
- **Edit mode** — composing/editing a message (the text editor)
- **Contacts mode** — viewing/editing the contacts file

---

## Text editor

### Buffer model

The editor operates on a **gap buffer**: a single array of characters with
a gap at the cursor position. Inserts and deletes at the cursor are O(1).
Moving the cursor shifts the gap.

The buffer stores the user's actual content. Wrap-inserted newlines are
NOT stored in the buffer — they are computed from the buffer content and
the current terminal width (see Line wrapping).

### Viewport

The viewport is a window into the buffer:
- `scroll_row` — first visible line (after wrapping)
- `cursor_row`, `cursor_col` — cursor position in buffer coordinates

When the cursor moves outside the viewport, the viewport follows.

### Line wrapping

Hard wrap, dynamically reflowed to the current terminal width.

The editor maintains the distinction between **user newlines** (the user
pressed Enter) and **wrap points** (inserted by the editor at word
boundaries to fit the terminal width). Only user newlines are stored in
the gap buffer. Wrap points are computed on the fly.

**How it works:**

1. The wrap column = current terminal width (minus any margin).
2. For each line in the buffer (delimited by user newlines), scan forward.
   When a line exceeds the wrap column, find the last space at or before
   the wrap column and break there.
3. The displayed text has newlines at wrap points, but the buffer does not.

**On terminal resize:**

1. Terminal width changes (SIGWINCH fires).
2. All wrap points are recalculated for the new width.
3. The screen is fully redrawn.

Example: user types 100 characters with no Enter.
- At 80-wide terminal: wraps at ~80 (word boundary), shows 2 lines.
- User resizes to 90-wide: wrap point moves to ~90, still 2 lines.
- User resizes to 40-wide: wraps at ~40, ~80, shows 3 lines.

The buffer content never changes on resize — only the computed wrap
points change.

**Default terminal size**: configurable in the client config file. This
sets the initial width, which determines the initial wrap column. The
user can resize at any time and wrapping follows.

### Keybinds

Configurable in the client config file. Two built-in schemes:

**Arrow keys (default):**
- Arrow keys: move cursor
- Home/End: start/end of line
- Page Up/Down: scroll by screenful
- Ctrl+S: save
- Ctrl+X: exit
- Ctrl+K: cut line
- Ctrl+U: paste
- Ctrl+F: search
- Ctrl+Z: undo

**Vim mode:**
- Normal mode: h/j/k/l movement, dd cut, p paste, / search, u undo
- Insert mode: i/a/o to enter, Esc to leave
- Command mode: :w save, :q quit, :wq save+quit

### Mouse support

When mouse reporting is enabled:
- **Click** — move cursor to clicked position
- **Scroll wheel** — scroll viewport up/down
- **Click+drag** — select text (tags selected cells with "selection")

### Clipboard

Copy/paste integrates with the system clipboard:
- **Linux**: pipe to/from `xclip -selection clipboard` or `xsel --clipboard`
- **macOS**: `pbcopy` / `pbpaste`
- **Windows**: `clip.exe` / PowerShell `Get-Clipboard`

Detection: try each command at startup, use the first one that exists.
Fall back to an internal yank buffer if none are available.

### Emojis

Emoji rendering depends on the terminal emulator and font. The editor:
- Treats emoji as 2-cell-wide characters (using Unicode East Asian Width
  or a lookup table for common emoji ranges)
- Renders them to the cell grid with a continuation cell
- Does not do emoji input — users paste from their system emoji picker

**Stretch goal**: a snippet drawer (Ctrl+E or :snippets in vim mode)
that opens a scrollable list of saved text. Users can save frequently
typed text (including emoji) here. Stored in the client config directory.

---

## Rendering pipeline (per frame)

```
1. Handle input events (keypress, mouse, resize)
2. Update editor/list/view state
3. Modify changed cells in back buffer (do NOT clear — tags persist)
4. Diff back vs front buffer
5. Collapse ANSI codes and emit minimal output to stdout
6. Copy changed cells from back to front
```

Rendering only happens when state changes. If no input arrives, the
process sleeps in the input read — zero CPU.

On resize: reallocate both buffers, reflow text, full redraw.

---

## Platform differences

| Concern | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Terminal | Any (xterm, alacritty, etc.) | Terminal.app, iTerm2 | Windows Terminal, ConEmu |
| Raw mode | `termios` via C module | Same (POSIX) | `SetConsoleMode` via C module |
| Resize | `SIGWINCH` | `SIGWINCH` | Console event |
| Clipboard | xclip/xsel | pbcopy/pbpaste | clip.exe/PowerShell |
| Mouse | ANSI escape sequences | Same | Same (Windows Terminal) |
| Build | cc/gcc | clang (Xcode CLI tools) | MSVC or MinGW |

The editor Lua code is identical across platforms. Platform differences
are isolated to:
- A small C module for raw terminal I/O (`rmail_term.c`)
- Clipboard command detection (pure Lua, checks for available commands)

---

## File structure

```
clients/
  editor-design.md          <- this file
  shared/
    editor.lua              <- text editor (gap buffer, viewport, wrapping)
    renderer.lua            <- double-buffered cell grid, ANSI output, tags
    term.lua                <- terminal setup, input parsing, resize
    rmail_term.c            <- raw mode, SIGWINCH (platform-specific C)
  linux/
    install.sh              <- bootstrap script
    rmail-client.lua        <- entry point
    lib/
      protocol.lua          <- wire protocol (frames, HTTP formatting)
      sync.lua              <- sync cycle (mirrors Android SyncManager)
      store.lua             <- local state (sync-state.json, files)
      ui.lua                <- screen layout, modes, navigation
  android/                  <- (moved from android/)
    ...existing Android app...
```

The `shared/` directory is symlinked or copied into each platform client
at build time. The editor, renderer, and terminal code are the same
everywhere — only `rmail_term.c` has platform-specific `#ifdef` blocks.

---

## Open items

- [ ] Decide crypto bootstrap approach (OpenSSL CLI vs embedded C decryptor)
- [ ] Implement tag-based batch update API (`buffer:update_tag()`)
- [ ] Snippet drawer UI (stretch goal)
- [ ] Emoji width lookup table
- [ ] Undo/redo system (stack of buffer diffs? or full snapshot per keystroke?)
