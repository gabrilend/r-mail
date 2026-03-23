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

---

## Connectivity check script — `scripts/check-connectivity.sh`

**Implemented.** A standalone script the user runs after opening their firewall.
Not part of install.sh — the firewall step and the install step can happen in
either order, so the check lives separately.

Two checks:

### 1. Hairpin NAT test

No daemon needed — the TCP handshake itself is the signal:

- **Hairpin NAT works:** packet reaches the machine, machine sends TCP RST ("connection refused" — nothing listening yet). Fast response.
- **Hairpin NAT doesn't work:** router drops the packet. Timeout.

The firewall must already be open for an accurate result (otherwise the OS drops the packet and mimics a false timeout). Run the probe immediately after the firewall step.

On failure:
```
Warning: your router does not appear to support hairpin NAT.

This means contacts on your local network cannot reach you using your
public IP address. They should use your local IP instead and add a
separate entry to their contacts file — see docs/ports-explained.md.
```

### 2. UPnP security test

Run `upnpc -s` to check whether the router responds to UPnP. If a valid IGD is found, warn the user:

```
Warning: your router has UPnP enabled.

UPnP is an unauthenticated protocol — any device on your local network
can open ports on your router without your approval. Malware commonly
exploits this. Consider disabling UPnP in your router's admin panel.

See docs/nat-traversal-report.md for details.
```

Only run this if `upnpc` was compiled or found during the install. Skip silently if unavailable.

The daemon already runs this check at startup via `nat_security_check` and notifies contacts. The install-time check gives the user an immediate heads-up without waiting for a contact to tell them.

---

## Documentation

**Implemented.**
- `docs/ports-explained.md` — new hairpin NAT section with the manual workaround and example contacts entries
- `README.md` — mention of `scripts/check-connectivity.sh` after the firewall setup section
