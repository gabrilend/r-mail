# #354 — Per-IP ports in the contacts file

## Problem

`contact.port` is a single scalar that applies to every address in
`contact.ips` (see #347 for the multi-IP model). A contact whose LAN
interface listens on one port and whose WAN port-forward lands on a
different one can't be expressed today.

## Design (confirmed with user: "data fallback, not code fallback")

Embed the port in the `ip` value when needed; otherwise fall back to
the contact-level `.port` as the default. The config file is explicit
about the default and about per-record overrides — no silent
code-level handling of special cases.

```
alice.port  = 8025
alice.ip    = 192.168.1.5:22          # LAN, overrides port
alice.ip    = alice.duckdns.org:8025  # WAN via DDNS
alice.ip    = [2001:db8::1]:8025      # IPv6, brackets required
alice.ip    = 198.51.100.7            # inherits alice.port (8025)
```

The existing `alice.port = 8025` line is the data-level default. A
line that wants a different port overrides it in place.

## Parser

```lua
local function parse_endpoint(value, default_port)
    -- [IPv6]:port
    local addr, port = value:match("^%[([^%]]+)%]:(%d+)$")
    if addr then return addr, tonumber(port) end
    -- [IPv6] alone (no port)
    addr = value:match("^%[([^%]]+)%]$")
    if addr then return addr, default_port end
    -- Bare IPv6 (contains `::` or ≥ 2 colons): port must not be inferred
    local colon_count = select(2, value:gsub(":", ":"))
    if colon_count >= 2 then return value, default_port end
    -- IPv4 or hostname with optional :port
    addr, port = value:match("^(.-):(%d+)$")
    if addr and port then return addr, tonumber(port) end
    return value, default_port
end
```

## Data model

- `contact.ips` stays — list of address strings (no port info), for
  callers that only need addresses (DNS comparison, LAN peer cache).
- `contact.endpoints` — new list of `{addr = "...", port = N}` pairs,
  one per `ip` line, with `default_port` taken from `contact.port`.
- `contact_hosts(c)` unchanged (still returns addresses).
- `contact_endpoints(c)` — new helper, returns the endpoint pair list
  in preferred order.

## Migration

Fully opt-in. A contacts file with no `HOST:PORT` syntax keeps working
bit-for-bit identically:

- `alice.ip = 192.168.1.5` + `alice.port = 8025` →
  `endpoints = [{addr = "192.168.1.5", port = 8025}]`.

Adding a per-ip port is a text edit a user makes by hand. `align_contacts`
preserves the `HOST:PORT` form (no re-parsing).

## Call sites

Every `http_post_batch_with_fallback` site currently passes
`hosts = contact_hosts(c)` and `port = c.port`. Under this change, a
site that needs the full list of (addr, port) pairs reads
`contact_endpoints(c)` and threads the per-entry port into the request
shape — probably `hosts_ports = [{host, port}, ...]` so the wrapper
can use the matching port per retry.

Sites where the port never varies per-address (the whole contact uses
one port) don't need to change beyond reading `contact.port` as today.

## Scope

Not needed until a real user has a mixed-port setup. Parking this with
the design written out so the next run has a starting point. Spawn into
implementation when the first LAN/WAN-different-port contact appears.

## Source

Spun out of #347 ("Phases 1, 2, 3" scope note). Design agreed with
user during that pass.

## Status

Superseded by #347 Phase 4.

The original design embedded ports in the ip value (`ip = host:port`)
with a `parse_endpoint` parser.  This was replaced by explicit indexed
fields (`ip[N]`/`port[N]`) which are simpler to parse and clearer to
read.  The `parse_endpoint` function has been removed.

See #347 for the current implementation.
