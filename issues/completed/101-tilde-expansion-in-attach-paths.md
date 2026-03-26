# 101 - Tilde Expansion in attach: Paths

## Current Behavior

When a user specifies an attachment path using tilde notation in an outbox file:

```
to: alice
attach: ~/pictures/photo.jpg

Here's the photo!
```

The daemon attempts to compress `~/pictures/photo.jpg` literally, which fails because:
1. The tilde is not expanded by Lua's `os.execute` when the path is quoted
2. The file appears not to exist from the daemon's perspective
3. The log shows: `failed to compress ~/pictures/photo.jpg for alice`

The user must use the full absolute path `/home/username/pictures/photo.jpg` for attachments to work.

## Intended Behavior

The daemon should expand `~` to the user's home directory before processing attachment paths:
- `~/pictures/photo.jpg` becomes `/home/ritz/pictures/photo.jpg`
- `~user/file.txt` could optionally expand to that user's home (lower priority)

This matches user expectations from shell behavior and reduces friction when composing messages.

## Suggested Implementation Steps

1. Create a `expand_tilde(path)` helper function in rmail.lua:
   ```lua
   local function expand_tilde(path)
       if path:sub(1, 1) == "~" then
           local home = os.getenv("HOME")
           if home then
               return home .. path:sub(2)
           end
       end
       return path
   end
   ```

2. Call `expand_tilde()` in `parse_outbox_file()` when extracting attachment paths (around line 1140)

3. Test with:
   - `~/file.txt` (home directory)
   - `/absolute/path.txt` (should be unchanged)
   - `relative/path.txt` (should be unchanged)

## Related Files

- `rmail.lua`: `parse_outbox_file()` function (line ~1113)
- `rmail.lua`: `compress_attachment()` function (line ~1279)

## Notes

- This issue was discovered while debugging attachment consent files not appearing on recipient machines
- The root cause was a Lua 5.4 compatibility bug (os.execute return value), but tilde paths also fail independently

## Fix Applied

Added `expand_tilde()` helper function at line ~172 and called it in `parse_outbox_file()` at line ~1226.

## Status

**FIXED** - Pending commit
