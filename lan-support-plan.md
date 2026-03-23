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

So both use cases are already handled. What's missing is:
1. Documentation explaining this (see below)
2. A startup check for hairpin NAT so users know they need LAN entries

---

## Hairpin NAT detection at startup

The daemon knows its own public IP (checked at startup for dynamic IP tracking) and its own port. It can test hairpin NAT by connecting to itself via the public IP and verifying the response.

**Test:**
1. `GET http://<own_public_ip>:<own_port>/` — same probe used for IP verification
2. Response should be `{"ok": true, "name": "<own_name>"}`
3. If connection succeeds and name matches → hairpin NAT works, no LAN entries needed
4. If connection fails or times out → hairpin NAT not supported

**On failure:** drop a one-time notice in the inbox explaining the situation and what to do:

```
Heads up: your router does not appear to support hairpin NAT.

This means contacts on your local network cannot reach you using your
public IP address (203.0.113.1). They should use your local IP instead
(e.g. 192.168.1.10) and add a separate entry to their contacts file.

See docs/ports-explained.md for details.
```

Track whether the notice has been sent in `.state/` so it only fires once (same pattern as UPnP warnings). Re-run the check on each startup; if hairpin NAT starts working (router firmware update, config change), suppress the notice going forward.

**Edge cases:**
- Public IP not yet known (first startup): skip the check, run it next cycle
- Firewall blocks loopback to public IP even though hairpin NAT works: this would be a false positive. The notice isn't harmful in that case — it's extra info the user doesn't need. Acceptable.
- No internet connection: public IP probe will already fail elsewhere; skip the hairpin check too

---

## Documentation needed

`docs/ports-explained.md` should get a section (or expand the existing local IP section) covering:
- What hairpin NAT is and why some routers don't support it
- How to add a LAN entry alongside a regular contact entry
- That the port number is still needed (it's the daemon's address), but no router rule is required

`README.md` or `docs/ports-explained.md` should mention that the port forwarding step can be skipped entirely for LAN-only setups, at the cost of not being reachable from outside the network.
