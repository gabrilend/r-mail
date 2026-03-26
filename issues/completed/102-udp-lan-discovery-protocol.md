# 102 - UDP LAN Discovery Protocol

## Current Behavior

When two rmail daemons are on the same LAN but their contacts files contain the public IP (required for external connectivity), communication fails if hairpin NAT is not supported by the router.

The current `lan_peers` cache only gets populated when a peer **successfully connects inbound**. This creates a chicken-and-egg problem:
1. A can't connect to B via public IP (hairpin NAT fails)
2. B never connects to A (hasn't sent anything yet)
3. Neither learns the other's LAN IP
4. Both keep trying the public IP, failing repeatedly

The workaround is to manually add a separate contact entry with the LAN IP, or temporarily edit the contacts file - neither is ideal.

## Intended Behavior

Daemons on the same LAN should automatically discover each other's LAN IPs using UDP broadcast, without requiring any manual configuration or successful TCP connection first.

When a contact's configured IP matches the local daemon's public IP (indicating same-network), the daemon should:
1. Send an encrypted UDP discovery request
2. Receive an encrypted response containing the peer's identity
3. Cache the peer's LAN IP (from the UDP packet's source address)
4. Use the LAN IP for subsequent TCP connections

This should be a two-way exchange - when B responds to A's discovery, B also learns A's LAN IP from the request's source address.

## Suggested Implementation Steps

### Phase 1: UDP Socket Setup

1. Add UDP socket listening on the same port as TCP (e.g., 8025)
2. Use `socket.udp()` from luasocket
3. Bind to `0.0.0.0:<port>` for receiving broadcasts

### Phase 2: Discovery Request (Sender Side)

1. **Trigger conditions:**
   - On daemon startup (for all same-network contacts)
   - On TCP connection timeout to a same-network contact (once per failed sync cycle)

2. **For each contact where `contact.ip == my_public_ip`:**
   - Create discovery packet: `RMAIL-DISCOVER <my_name> <my_port>`
   - Encrypt with contact's token (AES-256-GCM, same as TCP)
   - Send UDP to `255.255.255.255:<contact.port>` (broadcast)

3. **No persistent backoff needed:**
   - Startup discovery happens once per daemon start
   - Connection-failure discovery happens once per failed TCP attempt (not repeated within same sync cycle)
   - When either peer comes online, their startup discovery triggers mutual exchange

### Phase 3: Discovery Response (Receiver Side)

1. **On receiving UDP packet:**
   - Try trial decryption with each contact's token
   - If decryption succeeds, parse `RMAIL-DISCOVER <sender_name> <sender_port>`
   - Cache sender's LAN IP: `lan_peers[sender_name] = <packet_source_ip>`

2. **Send response:**
   - Create response packet: `RMAIL-HERE <my_name>`
   - Encrypt with sender's token
   - Send UDP unicast to `<packet_source_ip>:<sender_port>`

### Phase 4: Response Handling (Original Sender)

1. **On receiving UDP response:**
   - Try trial decryption
   - If successful, parse `RMAIL-HERE <responder_name>`
   - Cache responder's LAN IP: `lan_peers[responder_name] = <packet_source_ip>`
   - Log: `LAN discovery: learned %s is at %s`

### Phase 5: Integration

1. Modify `resolve_lan_host()` to check `lan_peers` cache (already does this)
2. No state file changes needed in `validate-router-settings.sh` (no persistent backoff)

## Packet Format

```
Discovery request (encrypted with recipient's token):
  [4-byte length][12-byte nonce][ciphertext][16-byte GCM tag]
  Plaintext: "RMAIL-DISCOVER <name> <port>"

Discovery response (encrypted with requester's token):
  [4-byte length][12-byte nonce][ciphertext][16-byte GCM tag]
  Plaintext: "RMAIL-HERE <name>"
```

Uses the same encryption format as TCP messages for consistency.

## Security Considerations

- All discovery packets are encrypted with the contact's shared token
- Only contacts with matching tokens can participate in discovery
- An eavesdropper sees encrypted UDP packets, learns nothing about identities
- No information leakage beyond "some rmail daemon is on this network"

## Edge Cases

1. **Contact's computer is off:** Broadcast gets no response. When they come online and send their startup discovery, both sides learn each other's IP.

2. **Multiple contacts on same network:** Each contact's discovery request uses their specific token, so responses are targeted correctly.

3. **IP changes (DHCP):** Next discovery cycle (on startup or connection failure) will learn the new IP.

4. **Roaming between APs without disconnect:** Connection failure triggers discovery, which re-learns the IP.

## Related Files

- `rmail.lua`: `resolve_lan_host()` function
- `rmail.lua`: `lan_peers` cache
- `rmail.lua`: `trial_decrypt()` function (reusable for UDP)
- `scripts/validate-router-settings.sh`: Add backoff reset

## Notes

- This feature was designed during debugging of same-LAN connectivity issues where hairpin NAT was not working
- The alternative (manual `lan_ip` field in contacts) was rejected as too cumbersome
- UDP was chosen because it supports broadcast without needing to know peer IPs

## Fix Applied

Added UDP LAN discovery protocol to rmail.lua:

1. **UDP socket setup** (line ~2898):
   - Created UDP socket bound to same port as TCP
   - Non-blocking mode for polling

2. **Encryption helpers** (lines ~999-1019):
   - `encrypt_packet(key, plaintext)` - encrypts data for UDP datagrams
   - `decrypt_packet(key, packet)` - decrypts UDP datagrams

3. **Discovery functions** (lines ~2954-3020):
   - `send_lan_discovery()` - broadcasts RMAIL-DISCOVER to same-network contacts
   - `handle_udp_discovery()` - processes incoming discovery requests/responses
   - `poll_udp_discovery()` - non-blocking poll for UDP packets

4. **Integration**:
   - Startup discovery sent when daemon starts (line ~3024)
   - UDP polling in main loop (line ~3232)
   - Connection-failure discovery triggered when TCP timeout occurs for same-network contact

5. **Trigger rules**:
   - Rule 1: On daemon startup - send discovery to all same-network contacts
   - Rule 2: On connection failure - send discovery once per failed contact (tracked via `discovery_sent` table)
   - Rule 3: On receiving discovery - always respond and cache their LAN IP

When a peer receives a discovery request, it caches the sender's LAN IP and sends a response. When a peer receives a response, it caches the responder's LAN IP. Both peers can then use `resolve_lan_host()` to connect via LAN IPs instead of public IPs.

## Status

**FIXED** - Committed
