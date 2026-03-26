# 201 - Modularize rmail.lua Codebase

## Current Behavior

The entire rmail daemon is contained in a single 3100+ line file (`rmail.lua`). This causes:

1. **Upvalue limit issues**: Lua/LuaJIT limit functions to 60 upvalues (captured variables from enclosing scopes). The `main()` function captures many module-level locals, approaching or exceeding this limit.

2. **Maintainability challenges**: Related functions are scattered throughout the file, making it harder to understand and modify specific subsystems.

3. **Testing difficulty**: Cannot easily test individual components in isolation.

## Intended Behavior

Split `rmail.lua` into focused modules that each handle a specific concern:

```
rmail.lua           -- Main entry point, config loading, main loop
libs/rmail_util.lua     -- File I/O, shell utilities, UUID generation
libs/rmail_nat.lua      -- NAT traversal (UPnP, NAT-PMP)
libs/rmail_http.lua     -- HTTP request/response, async batch requests
libs/rmail_handlers.lua -- Message handlers (deliver, delete, consent, etc.)
libs/rmail_sync.lua     -- Sync functions (outbox, inbox, attachments)
libs/rmail_crypto.lua   -- Already exists as C module, but add Lua wrappers
```

Each module returns a table of functions:
```lua
-- libs/rmail_nat.lua
local nat = {}
function nat.get_local_ip() ... end
function nat.create_mapping(port) ... end
return nat

-- rmail.lua
local nat = require("rmail_nat")
nat.create_mapping(8025)
```

## Implementation Steps

### Phase 1: Extract rmail_util.lua

1. Move utility functions:
   - `read_file`, `write_file`, `read_file_binary`, `write_file_binary`
   - `file_exists`, `list_files`
   - `shell_quote`, `run_hook`, `sanitize_filename`
   - `uuid`, `expand_tilde`

2. These have no dependencies on other rmail code, making them easy to extract.

### Phase 2: Extract rmail_nat.lua

1. Move the `nat` table and all its functions (already consolidated)
2. Move `tools` table (upnpc, natpmpc, zip, unzip paths)
3. Will need to pass `log`, `load_state`, `save_state` as dependencies or require rmail_util

### Phase 3: Extract rmail_http.lua

1. Move HTTP functions:
   - `parse_request`, `parse_request_string`
   - `send_response`, `send_raw_response`
   - `http_encrypt_and_send`, `http_read_encrypted_response`
   - `http_post_batch`

2. Move encryption helpers:
   - `derive_key`, `encrypt_packet`, `decrypt_packet`
   - `send_encrypted`, `recv_encrypted`, `trial_decrypt`

### Phase 4: Extract rmail_handlers.lua

1. Move message handlers:
   - `handle_deliver_message`, `handle_delete`
   - `handle_consent_*` functions
   - `handle_chunk`, `handle_cancel_transfer`
   - `handle_address_request`, `handle_address_notify`

### Phase 5: Extract rmail_sync.lua

1. Move sync functions:
   - `sync_outbox`, `sync_inbox`
   - `sync_address_notifications`
   - `check_consent_pending`, `send_consent_responses`
   - `send_next_chunks`, `send_attachment_cancellations`
   - Attachment compression/extraction functions

### Phase 6: Update rmail.lua

1. Require all modules
2. Keep only:
   - Config loading and paths
   - Contact file management
   - Main loop
   - LAN discovery (or extract to rmail_lan.lua)

## Dependency Management

Modules will need access to shared state. Options:

1. **Pass dependencies explicitly**: Each module function takes what it needs
   ```lua
   function sync.outbox(my_name, contacts, state_dir)
   ```

2. **Initialize modules with config**:
   ```lua
   local sync = require("rmail_sync")
   sync.init({state = STATE, inbox = INBOX, ...})
   ```

3. **Shared context table**:
   ```lua
   local ctx = {paths = paths, cfg = cfg, log = log, ...}
   local sync = require("rmail_sync").new(ctx)
   ```

Option 3 is cleanest - modules receive a context at initialization.

## Testing

After modularization, each module can be tested independently:

```lua
-- test_nat.lua
local nat = require("rmail_nat")
nat.init({log = print})
assert(nat.get_local_ip():match("%d+%.%d+%.%d+%.%d+"))
```

## Migration Strategy

1. Extract one module at a time
2. Keep backwards compatibility during transition
3. Run full test suite after each extraction
4. Commit each module extraction separately

## Related Files

- `rmail.lua`: Current monolithic implementation
- `libs/`: Directory for extracted modules
- `libs/rmail_crypto.so`: Existing C crypto module

## Notes

- This refactor was prompted by hitting Lua's 60-upvalue limit
- The `nat` table consolidation (done in issue 102 follow-up) provides a template
- Prioritize extracting modules that are most self-contained (util, nat)
- Consider also extracting LAN discovery to `rmail_lan.lua`

## Status

**OPEN** - Phase 2 feature
