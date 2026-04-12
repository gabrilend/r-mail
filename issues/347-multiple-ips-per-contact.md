# #347 — Multiple IPs per contact with auto-reordering and unified address type

## Problem

A contact currently has a single `.ip` field. That's brittle: if the
contact has both a LAN and WAN address, or a DDNS hostname as a fallback,
or a stable IPv6 alongside a changing IPv4, we can only pick one.

## Desired behavior

### Multiple IPs per contact

A contact can have more than one `ip` line in the config file. The daemon
tries each one in the order they appear until a connection succeeds.

```
alice.ip = 123.45.67.8
alice.ip = alice.duckdns.org
alice.ip = 2001:db8::1
alice.token = "..."
```

### Auto-grouping on load

If the same contact has `ip` entries scattered throughout the config, the
daemon re-writes the config so all of a contact's lines are contiguous.
Example:

```
# before
alice.ip = 123.45.67.8

... some stuff

bob.ip = 9.8.7.6
bob.token = "..."

... more stuff

alice.ip = 98.76.54.32
```

Becomes:

```
# after
alice.ip = 123.45.67.8
alice.ip = 98.76.54.32

... some stuff

bob.ip = 9.8.7.6
bob.token = "..."

... more stuff
```

### Unified address type

A single `ip` field accepts IPv4, IPv6, or a DNS hostname — the daemon
detects which by parsing. No separate `ip`, `ipv6`, `hostname` fields.

Overlaps with #311 (DNS hostnames in contacts) on the hostname-detection
and resolution plumbing. #311 handles the case where `ip` *is* a hostname;
this issue generalises to "n addresses of mixed type" on top of that.

### Stretch: promote the winning address

When the daemon connects, if the address that succeeds is not the first
one in the list, move it to the top of that contact's block on disk. The
fast path for future connections then matches reality.

## Source

From `issues/new-issue-todo`.
