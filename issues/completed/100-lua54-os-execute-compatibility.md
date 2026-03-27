# 100 - Lua 5.4 os.execute Compatibility

## Current Behavior

Attachment compression and extraction always fails with the error:
```
failed to compress /path/to/file.jpg for recipient
```

This occurs even when the zip command succeeds, because the return value check is incompatible with Lua 5.4.

## Root Cause

In `compress_attachment()` (line 1288) and `handle_attachment_chunk()` (line 1605):

```lua
local ret = os.execute(ZIP .. ' ...')
if ret ~= 0 then return nil, nil, nil end
```

**Lua 5.1/5.2:** `os.execute` returns `0` on success
**Lua 5.4:** `os.execute` returns `true` on success, `nil` on failure

The check `true ~= 0` evaluates to `true` (boolean is not equal to number), causing the function to treat success as failure.

## Intended Behavior

Attachment compression and extraction should work correctly on both Lua 5.1+ and Lua 5.4+.

## Fix Applied

Changed the return value checks from:
```lua
if ret ~= 0 then
```

To:
```lua
if not ret then
```

This works for both Lua versions:
- Lua 5.1: `0` is truthy, `not 0` is false (success path taken)
- Lua 5.4: `true` is truthy, `not true` is false (success path taken)
- Both: `nil`/`false` are falsy, `not nil` is true (failure path taken)

## Files Changed

- `rmail.lua` line 1288: `compress_attachment()` return value check
- `rmail.lua` line 1607: `handle_attachment_chunk()` return value check

## Testing

After fix:
```
2026-03-25 17:XX:XX sent attachment request to sorelu: photo.jpg
```

Before fix:
```
2026-03-25 17:XX:XX failed to compress /path/to/photo.jpg for sorelu
```

## Status

**FIXED** - Committed
