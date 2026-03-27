# 202 - Fix Chunk Response Parsing

## Current Behavior

Two bugs in the chunk transfer response handling:

1. **Missing status in results**: `http_post_batch` returns `{ok, data}` but code at lines 2293 and 2331 checks `results[i].status`. This means `status == 404` checks always fail.

2. **Wrong data access in send_next_chunks**: The code checks `results[1].missing` and `results[1].cancelled` but these fields are inside `results[1].data`, not at the top level.

## Intended Behavior

1. `http_post_batch` should return `{ok, status, data}` so status codes can be checked.

2. `send_next_chunks` should access `results[1].data.missing` and `results[1].data.cancelled`.

## Fix Applied

1. Changed line 1239 to include `status` in the result:
   ```lua
   results[i] = {ok = e.ok, status = e.status, data = e.data}
   ```

2. Changed `send_next_chunks` to extract `resp = results[1].data or {}` and access `resp.missing` and `resp.cancelled`.

## Related Files

- `rmail.lua`: `http_post_batch`, `send_next_chunks`

## Status

**FIXED** - Pending commit
