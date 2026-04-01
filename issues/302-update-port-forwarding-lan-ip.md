# Update port forwarding after LAN IP change (optional)

## Description

sorelu's LAN IP changed from 192.168.0.8 to 192.168.1.60. If using manual
port forwarding, the router rule for port 8027 still points to the old IP.

## Action

Update router's port forwarding rule: port 8027 → 192.168.1.60

Or set a DHCP reservation so the LAN IP doesn't change again.

## Status

Optional — only relevant if sorelu is on the original network and using
manual port forwarding.
