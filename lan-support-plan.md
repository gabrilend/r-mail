# LAN Support Plan

Two use cases to accommodate:

1. **No router access** — shared housing, ISP-locked router, etc. User cannot set up port forwarding at all.
2. **No hairpin NAT** — user has router access and port forwarding configured, but the router doesn't loopback public-IP traffic back to a LAN device. Contacts on the same network can't reach each other using the public IP.

---

## LAN connections already work — no format changes needed

The current contacts format already supports LAN-to-LAN connections. Users who need to reach a contact on the same network can add a second entry with the contact's local IP:

```
bob.ip    = 203.0.113.1
bob.port  = 8025
bob.token = "shared-secret"

bob_home.ip    = 192.168.1.20
bob_home.port  = 8025
bob_home.token = "shared-secret"
```

`bob` reaches him from anywhere. `bob_home` reaches him only on the LAN, but requires no port forwarding rule on the router — LAN traffic bypasses NAT entirely.

**The port number is still required** in the contacts entry. The port is the address of the daemon's listening socket; any TCP connection (LAN or internet) needs it. What's not required for LAN connections is the port forwarding *rule* on the router — those rules only apply to inbound internet traffic. The OS firewall rule (which is needed anyway for external access) is sufficient for LAN traffic.

This handles both use cases manually. The automatic approach below eliminates the need for separate entries.

---

## Hairpin NAT detection — install script

The install script should test hairpin NAT after the firewall setup step. No daemon needed — the TCP handshake itself is the signal:

- **Hairpin NAT works:** packet reaches the machine, machine responds with TCP RST ("connection refused" — nothing is listening yet). Fast response.
- **Hairpin NAT doesn't work:** router drops the packet. Timeout.

The firewall must already be open for this test to work, otherwise the OS drops the packet and mimics a false timeout. Since the install script walks through firewall setup, run the probe immediately after.

Persist the result to `.state/hairpin_nat_tested`. On a clean install this runs once and is done. If a user wants to re-test (new router, firmware update), they delete the state file and re-run the install script or restart the daemon.

**On failure, print during install and drop a notice in inbox on first startup:**

```
Heads up: your router does not support hairpin NAT.

This means contacts on your local network cannot reach you using your
public IP address (203.0.113.1). Either:
  - They add a separate entry using your local IP (see docs/ports-explained.md), or
  - rmail's automatic LAN discovery handles it transparently (see below).
```

---

## Automatic LAN discovery — hairpin NAT workaround

Instead of requiring users to add manual `bob_home` entries, the daemon can discover contacts on the LAN automatically when a connection fails.

**Trigger condition:** connection to a contact times out AND the contact's IP matches the daemon's own public IP. This combination reliably indicates a hairpin NAT failure — both devices are behind the same router.

**Discovery protocol (UDP broadcast):**

1. Daemon broadcasts on LAN (UDP, port TBD — pick a fixed port, e.g. 8026 or same as rmail port):
   ```json
   {"type": "discover", "looking_for": "alice", "from": "bob", "nonce": "<random>",
    "auth": "<hmac-sha256(token, nonce)>"}
   ```
2. Alice's daemon receives the broadcast, finds "bob" in its contacts, verifies the HMAC using the shared token.
3. Alice's daemon responds directly to Bob (unicast):
   ```json
   {"type": "discover_response", "name": "alice", "port": 8025,
    "auth": "<hmac-sha256(token, nonce)>"}
   ```
   Response auth uses the same nonce so Bob can verify it.
4. Bob's daemon retries the connection using Alice's LAN IP (source IP of the UDP response) and port.
5. Bob's daemon caches the LAN address for the session (not persisted — LAN IPs change).

**Security:** the shared token authenticates both sides. An eavesdropper on the LAN learns that Bob is looking for Alice, but learns nothing else (no token, no message content). The nonce prevents replay attacks.

**No changes needed to the contacts file.** Discovery is a transparent fallback, invisible to the user.

**Edge cases:**
- Multiple rmail daemons on the LAN: all hear the broadcast, only the one with a matching contact and valid token responds.
- Alice is offline: no response, Bob falls back to existing retry logic.
- Discovery UDP port blocked by OS firewall: falls back gracefully (no discovery, user gets the manual-entry notice instead). The daemon should open the discovery port alongside the main port during setup.

---

## Documentation needed

`docs/ports-explained.md` — new section covering:
- What hairpin NAT is and why some routers don't support it
- The manual workaround (separate LAN contact entry)
- That automatic discovery handles it transparently when both daemons are updated

`README.md` or `docs/ports-explained.md` — note that port forwarding can be skipped entirely for LAN-only setups.
