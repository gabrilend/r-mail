# 103 - Function Ordering: remove_recipient_from_file

## Current Behavior

When a contact deletes a message from their inbox (triggering `/delete`), the daemon crashes with:

```
attempt to call global "remove_recipient_from_file" (a nil value)
```

This happens because `remove_recipient_from_file` is called at line ~816 (in `handle_delete`) but defined at line ~1156.

In Lua, functions must be defined before they are called (unless using forward declarations).

## Root Cause

The function was likely added later and placed near related functions (`parse_outbox_file`, `remove_attach_from_file`) without checking call order.

## Fix Applied

Moved `remove_recipient_from_file` function definition from line 1156 to line 749 (after `release_zip`, before `handle_delete`).

Added vimfold markers and documentation comment per project conventions.

## Files Changed

- `rmail.lua`: Moved function definition earlier in file

## Status

**FIXED** - Committed
