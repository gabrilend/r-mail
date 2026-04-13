# #356 — `list_files` should skip directories and non-regular entries

## Problem

`list_files(dir)` shells to `ls -1` and returns every non-hidden
entry, including subdirectories. Callers assume each returned name
is a regular file (they pass it to `read_file`, `parse_outbox_file`,
size reads, etc.).

Most of the time this is harmless — `read_file` on a directory
fails gracefully (EISDIR on Linux, `io.open` returns nil) and the
caller skips. But one edge case is real: if a user creates a
directory in `inbox/` whose name collides with an
`<something>-consent-to-download-form` file or an in-progress
"Receiving …" progress file, `consent_cancelled()` reads nil,
returns true, and the daemon cancels or declines the transfer.

## Fix

Change `list_files`:

```lua
local function list_files(dir)
    local files = {}
    local handle = io.popen('ls -1p ' .. shell_quote(dir) .. ' 2>/dev/null')
    if handle then
        for name in handle:lines() do
            -- `ls -1p` appends `/` to directory entries.
            if name:sub(1, 1) ~= '.' and name:sub(-1) ~= '/' then
                files[#files + 1] = name
            end
        end
        handle:close()
    end
    return files
end
```

`-p` works on GNU and BSD `ls` (it's in POSIX).

Callers stay unchanged.

## Scope

Affects `sync_outbox`, `sync_inbox`, the Android attachments API,
and the shared-device file list. None of them want directories;
all four get safer behavior.

## Status

Not started. Small, local fix. Spin this up the next time someone
actually creates a directory in one of these dirs and something
misbehaves.
