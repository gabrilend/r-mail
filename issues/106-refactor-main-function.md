# Refactor main() — LuaJIT 60 upvalue limit

## Problem

LuaJIT limits functions to 60 upvalues (local variables from enclosing scopes
that closures reference). The `main()` function in rmail.lua has exceeded this
limit due to accumulated feature additions. The daemon crashes on startup with:

```
function at line 3036 has more than 60 upvalues
```

Standard Lua 5.2+ has a 200 upvalue limit and doesn't hit this. LuaJIT's
limit is 60, inherited from Lua 5.1.

## Root cause

`main()` is a monolithic function (~500 lines) containing:
- Config loading and path setup
- NAT security checks and port forwarding
- LAN IP detection and peer caching
- Server socket setup
- The main accept/process loop
- The sync cycle (outbox, inbox, address notifications, consent, chunks)
- Sync-now trigger file checking
- NAT mapping renewal

Each feature added more `local` variables, and the closures within main
(the request handler, the sync cycle, resolve_lan_host, etc.) capture them
as upvalues.

## Fix

Break `main()` into smaller functions that receive their dependencies as
arguments or via a shared state table. Options:

1. **State table**: consolidate related locals into tables
   (`local server_state = {lan_peers = {}, last_sync = 0, interval = 10, ...}`)
   Each table counts as one upvalue regardless of how many fields it has.

2. **Extract functions**: move the request handler, sync cycle, and setup code
   into separate top-level functions that take the state table as an argument.

3. **Both**: state table + extracted functions. Cleanest but most work.

Option 1 is the quickest fix. Option 3 is the right long-term approach,
especially in preparation for the coroutine-based architecture (issue #104).

## Status

- [ ] Consolidate locals into state tables to fix the crash (quick fix)
- [ ] Extract request handler into its own function
- [ ] Extract sync cycle into its own function
- [ ] Extract setup/init code into its own function
- [ ] Review for further decomposition opportunities
