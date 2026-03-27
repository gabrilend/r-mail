# 203 - LAN Discovery Router IP Rewrite

## Current Behavior

When a UDP broadcast is received, some routers rewrite the source IP address to their own IP (e.g., 192.168.0.1). This causes LAN discovery to cache the router's IP instead of the peer's actual LAN IP.

Example: kuvalu broadcasts discovery, sorelu receives it but sees source IP as 192.168.0.1 (router), then sorelu tries to connect to the router instead of kuvalu.

## Intended Behavior

LAN discovery should work regardless of router source address rewriting by including the sender's LAN IP in the encrypted payload itself.

## Fix Applied

Changed discovery packet format to include sender's LAN IP:

**Before:**
- Request: `RMAIL-DISCOVER <name> <port>`
- Response: `RMAIL-HERE <name>`

**After:**
- Request: `RMAIL-DISCOVER <name> <port> <lan_ip>`
- Response: `RMAIL-HERE <name> <lan_ip>`

The receiver now uses the LAN IP from the payload (which is encrypted and authenticated) rather than the UDP source address (which can be rewritten by routers).

Also send the response back to the payload's LAN IP, not the UDP source.

## Related Files

- `rmail.lua`: `send_lan_discovery`, `handle_udp_discovery`, `on_connection_timeout`

## Notes

- This issue was discovered when sorelu logged "using LAN IP 192.168.0.1 for kuvalu" - the router was inserting its own IP
- The encrypted payload cannot be tampered with, so including the IP there is secure
- Backwards compatible: old daemons will see the extra field but won't parse it correctly (discovery will fail gracefully)

## Status

**FIXED** - Committed
