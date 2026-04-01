# IPv6 support

## Why

IPv6 gives every device a globally unique address. No NAT, no port
forwarding, no hairpin NAT problems, no "simultaneous IP change" issue.
A device's IPv6 address is directly reachable from anywhere on the internet.

This would eliminate the single biggest source of setup friction in rmail:
router configuration.

## What changes

### Contacts file
Currently: `alice.ip = 203.0.113.1` (IPv4)
With IPv6: `alice.ip = 2001:db8::1` (or both — dual-stack)

The contacts parser and all IP-handling code would need to accept both
IPv4 and IPv6 addresses.

### Socket binding
Currently: `socket.bind("0.0.0.0", port)` (IPv4 only)
With IPv6: also bind `::` (IPv6 any) or use dual-stack socket

LuaSocket supports IPv6 via `socket.tcp6()` and `socket.udp6()`.

### No port forwarding needed
With IPv6, the device IS the router endpoint. The contacts file entry
is the device's actual address, not the router's. No NAT translation,
no forwarding rules.

### Firewall still needed
IPv6 doesn't mean no firewall. The OS firewall (ufw, nftables, iptables)
still needs the port opened. But the router doesn't need configuration.

### Dynamic IPv6 addresses
ISPs can still change IPv6 prefixes (less common than IPv4 reassignment
but it happens). rmail's existing dynamic IP detection would need to
check IPv6 addresses too. The privacy extensions (RFC 4941) generate
temporary addresses — rmail should use the stable SLAAC address, not
the privacy address.

### LAN discovery
IPv6 has link-local addresses (fe80::) that are always available and
never change. The UDP LAN discovery could use these instead of scanning
subnets — much cleaner than the current IPv4 multicast + subnet scan.

### Dual-stack
Most networks today are dual-stack (both IPv4 and IPv6). rmail should
try IPv6 first (no NAT overhead), fall back to IPv4. The contacts file
could have both:
```
alice.ip   = 203.0.113.1
alice.ipv6 = 2001:db8::1
```

Or detect automatically: if the address contains `:`, it's IPv6.

## Scope

- [ ] Accept IPv6 addresses in contacts file
- [ ] Bind dual-stack sockets (IPv4 + IPv6)
- [ ] Outgoing connections: try IPv6 first, fall back to IPv4
- [ ] Dynamic IP detection for IPv6 prefixes
- [ ] LAN discovery via IPv6 link-local
- [ ] Update install.sh to detect and display IPv6 addresses
- [ ] Update validate-router-settings.sh for IPv6
- [ ] Update Android client to handle IPv6 addresses
- [ ] Documentation: explain that IPv6 eliminates port forwarding

## Status

Not yet implementing. This is a significant but high-value change —
it would make rmail dramatically easier to set up for anyone on an
IPv6-capable network.
