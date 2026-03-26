# 204 - Fix Partial Send for Large Payloads

## Current Behavior

Attachment chunk transfers fail with "chunk X/Y failed, will retry" even though regular messages work fine.

## Root Cause

`http_encrypt_and_send()` used a single `sock:send()` call without looping for partial sends:

```lua
local sent = e.conn:send(uint32_be(#frame) .. frame)  -- BUG!
```

On non-blocking sockets, `send()` may only send what fits in the kernel's TCP buffer (~64-256KB) and return early. For small messages this works, but large payloads (5MB chunks → ~7MB encrypted) get truncated silently.

The receiver gets incomplete/garbage data, fails to decrypt, sends no response, and the sender times out.

## Fix Applied

Changed `http_encrypt_and_send()` to loop until all data is sent:

```lua
e.conn:settimeout(30)
local sent = 0
while sent < #data do
    local bytes, err, partial = e.conn:send(data, sent + 1)
    if bytes then
        sent = sent + bytes
    elseif partial and partial > 0 then
        sent = sent + partial
    else
        -- handle error
    end
end
```

Also fixed the same bug in `send_encrypted()` for consistency.

## Debugging Journey

This bug was obscured by a long detour into LAN discovery issues:
- Router rewriting UDP source IPs → fixed by including LAN IP in payload
- Broadcast not working → added multicast + subnet scan
- `nat.get_local_ip()` failing under systemd → fixed NixOS paths

None of these were the actual problem. The real bug was always the partial send.

## Related Files

- `rmail.lua`: `http_encrypt_and_send()`, `send_encrypted()`

## Status

**FIXED** - Attachments now transfer successfully
