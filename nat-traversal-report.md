# NAT Traversal Notes — r-mail

## What we want

1. Automatically forward a port through the user's NAT/router so contacts can reach the rmail daemon
2. Fall back gracefully if automatic forwarding isn't available
3. Understand the security implications — these protocols were designed in an era of naivety
4. Make an informed decision about whether to use them, and how to warn users


## Part 1: The NAT problem

Every home router does NAT (Network Address Translation). Your ISP gives you one public IP, and the router shares it among all your devices by rewriting packet headers. Outgoing connections work fine — the router remembers which internal device started the connection and routes replies back. Incoming connections are the problem. If someone on the internet sends a packet to your public IP on port 8025, the router has no idea which internal device it's for. It drops it.

This is why rmail currently requires manual port forwarding. You log into your router's admin page and add a rule: "forward external port 8025 to internal 192.168.1.50:8025." Now packets arrive at your daemon. It works, but:

- You need router admin access
- You need to know your machine's local IP
- The local IP might change (DHCP lease renewal)
- Every user has to do this manually, and router UIs are all different

For a tool that's supposed to be simple (drop files in a folder, they get sent), requiring router configuration is a friction point. So the question is: can we automate it?

The answer is yes, but the protocols that do it have serious security baggage.


## Part 2: UPnP IGD (Internet Gateway Device)

### Protocol overview

UPnP IGD is the most widely supported automatic port forwarding protocol. Almost every consumer router supports it (usually enabled by default). Here's how it works:

**Step 1: Discovery (SSDP).** The client sends a multicast UDP packet to 239.255.255.250:1900 — the SSDP (Simple Service Discovery Protocol) address. This is a "who's out there?" broadcast on the LAN. Any UPnP-capable router responds with its description URL.

```
M-SEARCH * HTTP/1.1
HOST: 239.255.255.250:1900
MAN: "ssdp:discover"
MX: 3
ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1
```

The router replies with something like:

```
HTTP/1.1 200 OK
LOCATION: http://192.168.1.1:5000/rootDesc.xml
ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1
```

**Step 2: Description.** The client fetches the XML description document from that URL. It contains the router's device info and a list of services, including WANIPConnection or WANPPPConnection — the services that manage port forwarding.

**Step 3: Control (SOAP over HTTP).** To add a port mapping, the client sends a SOAP XML request to the control URL found in the description:

```xml
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>8025</NewExternalPort>
      <NewProtocol>TCP</NewProtocol>
      <NewInternalPort>8025</NewInternalPort>
      <NewInternalClient>192.168.1.50</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription>rmail</NewPortMappingDescription>
      <NewLeaseDuration>0</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>
```

That's a lot of XML for "please forward port 8025 to me." But it works.

### CLI tool: upnpc (miniupnpc)

miniupnpc is the standard command-line UPnP client. Usage:

```bash
# List current port mappings
upnpc -l

# Add a TCP port mapping (external 8025 -> internal 8025)
upnpc -a 192.168.1.50 8025 8025 TCP

# Delete a port mapping
upnpc -d 8025 TCP

# Get external (public) IP address
upnpc -s
```

It handles the SSDP discovery, XML parsing, and SOAP calls internally. Available in most package managers (`miniupnpc` on Arch/Debian, `miniupnpc` on NixOS).

### Security model: none

UPnP IGD has **no authentication**. Any device on the LAN can add or remove port mappings. The design philosophy was "devices on your home network are trusted." This made sense in 2001 when UPnP was designed — your LAN was a few computers you owned.

It does not make sense in 2024 when your LAN includes: your phone, your spouse's phone, your kids' tablets, smart TVs, IoT lightbulbs, a robot vacuum, a smart speaker, and whatever malware any of them might be running.

Any compromised device on your network can:
- Open any port on your router, exposing internal services to the internet
- Remove existing port mappings (denial of service)
- Redirect traffic by changing mappings

### UPnP Device Protection: the dead fix

The UPnP Forum recognized this problem and published the Device Protection extension. It adds:
- TLS for the control channel
- ACLs (access control lists) per device
- Authentication via login credentials or device identity

In theory, this would fix UPnP's security. In practice, it's a dead spec. Near-zero router adoption. I couldn't find a single consumer router that implements Device Protection. The spec came too late — by then, the security community had moved to "just disable UPnP entirely" as the standard recommendation. Router vendors had no incentive to implement a complex extension when the advice from every security researcher was to turn the whole thing off.


## Part 3: NAT-PMP (NAT Port Mapping Protocol)

### Protocol overview

NAT-PMP (RFC 6886) was Apple's answer to UPnP's complexity. Where UPnP uses multicast discovery, XML descriptions, and SOAP envelopes, NAT-PMP uses a simple binary UDP protocol on port 5351. The gateway address is assumed to be the default route (no discovery needed).

A port mapping request is 12 bytes:

```
  0                   1
  0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+
 |  Version (0)  | Opcode |
 +-+-+-+-+-+-+-+-+-+-+-+-+
 |     Reserved (0)       |
 +-+-+-+-+-+-+-+-+-+-+-+-+
 |  Internal Port         |
 +-+-+-+-+-+-+-+-+-+-+-+-+
 |  External Port         |
 +-+-+-+-+-+-+-+-+-+-+-+-+
 |  Lifetime (seconds)    |
 |                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+
```

Compare that to the SOAP XML monster above. You send 12 bytes to your gateway's port 5351, and it responds with the mapping details. That's it.

### CLI tool: natpmpc

natpmpc is the standard NAT-PMP client. Usage:

```bash
# Get external (public) IP address
natpmpc

# Add a TCP port mapping (external 8025, lifetime 3600 seconds)
natpmpc -a 8025 8025 tcp 3600

# Add a UDP port mapping
natpmpc -a 8025 8025 udp 3600
```

Available via `libnatpmp` in most package managers.

### Mapping lifetimes and renewal

Unlike UPnP (where mappings can be permanent with `LeaseDuration=0`), NAT-PMP mappings have explicit lifetimes. The router will delete the mapping after the lifetime expires. The RFC recommends:

- Request a lifetime of 3600 seconds (1 hour)
- Renew at half the granted lifetime (so every 30 minutes for a 1-hour mapping)
- On shutdown, send a mapping request with lifetime 0 to delete it

This is actually better design than UPnP's permanent mappings. If a device crashes without cleaning up, the mapping disappears on its own after the lifetime expires. UPnP permanent mappings stick around forever — stale rules accumulate.

### Security model: also none

NAT-PMP has the same trust model as UPnP. Any device on the LAN can create or delete mappings. No authentication, no authorization. The RFC acknowledges this:

> "NAT-PMP is designed for use in residential and small office networks where mutual trust exists between devices."

Same assumption, same problem.


## Part 4: PCP (Port Control Protocol)

### Protocol overview

PCP (RFC 6887) is the successor to NAT-PMP. It's backward compatible — a PCP server can understand NAT-PMP requests — but extends the protocol significantly:

- **IPv6 support** — NAT-PMP was IPv4 only
- **Firewall rule management** — not just NAT, but also stateful firewalls
- **Third-party mappings** — one device can request a mapping on behalf of another
- **Extension mechanism** — opcodes for future functionality

The wire format is still binary and UDP-based (port 5351), but packets are larger and more structured than NAT-PMP.

### PCP Authentication (RFC 7652)

This is where it gets interesting — and disappointing.

RFC 7652 defines an authentication mechanism for PCP. On paper, it's thorough:

- **EAP (Extensible Authentication Protocol)** — the same framework used in enterprise WiFi (WPA-Enterprise)
- **HMAC-based message authentication** — every PCP message gets a cryptographic signature
- **Session management** — authenticated sessions with nonces to prevent replay attacks
- **Key management** — derived session keys, key lifetime tracking
- **Downgrade detection** — prevents an attacker from forcing unauthenticated PCP

In theory, this solves the fundamental problem. Only authenticated devices can create port mappings. An attacker on your LAN can't open ports without credentials. Great.

In practice: **it doesn't exist.**

PCP Authentication requires EAP infrastructure. That means a RADIUS server (or equivalent) on your network, just to manage port forwarding credentials. No consumer router ships with a RADIUS server. No consumer router implements RFC 7652. I searched for implementations — real, deployed, shipping-in-a-product implementations — and found none. There are academic papers discussing it. There are RFC references to it. There are no products.

The spec requires the kind of infrastructure you'd find in an enterprise network, where you already have network engineers who can just configure the firewall directly. The people who NEED automatic port forwarding (home users) can't run the infrastructure that PCP Authentication requires. The people who CAN run the infrastructure don't need automatic port forwarding.

**Verdict:** Secure on paper. Useless in practice. The only PCP authentication that exists is the unauthenticated kind.


## Part 5: Threat model

### The fundamental flaw

All three protocols (UPnP, NAT-PMP, PCP without authentication) share the same fundamental flaw: **any device on the LAN can open any port on the router, with no authentication**.

Your router's firewall is supposed to be the barrier between the internet and your internal network. These protocols let any device punch holes in that barrier, by design. The router can't distinguish between "rmail legitimately requesting port 8025" and "malware requesting port 22 to expose your SSH server."

### Real-world exploitation

This isn't theoretical. It's been exploited at scale.

**Conficker worm (2008):** One of the largest malware outbreaks in history. Conficker used UPnP to open ports on infected machines' routers, allowing it to receive commands from its botnet controllers and propagate to other networks. This was one of the first major demonstrations that UPnP was a real attack vector, not just a theoretical one.

**Mirai botnet (2016 and ongoing):** Mirai and its variants use UPnP to create relay/proxy chains through compromised routers. The botnet opens port mappings to route traffic through residential networks, making the attack traffic appear to come from legitimate IPs. This is still actively happening.

**Scale of exposure:** A 2013 Rapid7 study found **81 million IPs** responding to UPnP discovery requests from the internet (routers with UPnP exposed on the WAN interface — a misconfiguration, but a common one). Of those, **17.25 million** had remotely accessible UPnP SOAP services, meaning an attacker on the internet could add port mappings without even being on the LAN.

### Specific CVEs

The UPnP protocol stack is complex (XML parsing, SOAP, HTTP), and implementations have been riddled with vulnerabilities:

- **CVE-2013-0230:** Buffer overflow in the libupnp SOAP parser. Affects millions of devices. Remote code execution via a crafted SOAP request. The irony: the protocol designed to make networking easier contained a bug that let attackers take over your router.

- **CVE-2014-8361:** Command injection in Realtek's UPnP implementation (used in many router chipsets). An attacker sends a specially crafted SOAP request and gets shell access on the router.

- **CVE-2020-12695 (CallStranger):** A design flaw in UPnP that allows an attacker to use UPnP SUBSCRIBE callbacks to exfiltrate data, perform DDoS amplification, and scan internal networks. This is a protocol-level flaw, not an implementation bug — it affects every compliant implementation.

### NAT-PMP exposure

NAT-PMP hasn't escaped either. A 2014 Rapid7 scan found **1.2 million devices** with NAT-PMP publicly accessible on the internet (port 5351 open on the WAN interface). With public NAT-PMP access, an attacker can:

- **Hijack DNS:** Create a mapping that redirects the router's DNS traffic through the attacker's server. All devices on the LAN now resolve domains through the attacker.
- **Intercept traffic:** Create mappings that route internal traffic through external hosts.
- **Map the internal network:** NAT-PMP responses reveal internal IP addresses and existing port mappings.

### Attack scenarios

The realistic attacks against rmail's use case:

1. **Malware opens a port for C2 (command and control).** A compromised IoT device on your LAN uses UPnP to open a port, giving the attacker a persistent backdoor into your network. Your router's firewall is now Swiss cheese. This has nothing to do with rmail — it's the background risk of having UPnP enabled at all.

2. **Attacker creates a relay.** If your router's UPnP is exposed to the internet (misconfigured or vulnerable), an attacker can create port mappings to relay traffic through your IP. Your IP shows up in abuse logs. You get the angry emails from ISPs.

3. **Mapping hijack.** Malware on your LAN deletes rmail's port mapping and creates its own on the same port, intercepting messages meant for your daemon.


## Part 6: Secure alternatives

### Manual port forwarding (the gold standard)

Log into your router, add the rule yourself. This is the most secure option because:

- Only someone with admin credentials can do it
- The rule is explicit and visible
- Malware on a LAN device cannot create, modify, or delete it
- It survives router reboots (unlike some UPnP mappings)

The downside is the user experience — you need to know what you're doing, and every router has a different admin interface. But for a security-conscious tool like rmail, this is the right default.

### VPN tunnels (WireGuard, Tailscale)

A VPN creates a private network between your devices. All devices on the VPN can reach each other directly — no port forwarding needed at all. The traffic is encrypted and authenticated at the network layer.

- **WireGuard:** Lightweight, fast, modern. You'd run a WireGuard server on a VPS or a machine with a public IP, and both rmail peers connect to it. They can then reach each other via WireGuard IPs.
- **Tailscale/Nebula:** Mesh VPNs that handle the configuration automatically. Tailscale uses WireGuard under the hood but adds automatic key management and NAT traversal (via DERP relay servers). No port forwarding, no router configuration.

This is the cleanest solution if you're willing to run (or pay for) VPN infrastructure. It sidesteps the entire NAT problem.

### SSH port forwarding

If you have SSH access to a machine with a public IP:

```bash
# Forward remote port 8025 to local port 8025
ssh -R 8025:localhost:8025 user@public-server
```

Now anyone connecting to public-server:8025 reaches your local rmail daemon. The tunnel is encrypted (SSH) and authenticated (SSH keys). No UPnP, no router configuration.

Downside: requires an SSH server somewhere, the tunnel needs to stay alive (autossh helps), and it adds latency.

### STUN/TURN/ICE

These are the protocols behind WebRTC's NAT traversal:

- **STUN** (Session Traversal Utilities for NAT): Discovers your public IP and port mapping from the outside. Helps with "easy" NATs (full cone, restricted cone).
- **TURN** (Traversal Using Relays around NAT): When direct connection fails, relay traffic through a server. Always works, but requires relay infrastructure.
- **ICE** (Interactive Connectivity Establishment): Tries multiple methods (direct, STUN, TURN) and picks the best one that works.

The security model is better — the relay server authenticates clients, and no ports are opened on the router. But you need relay infrastructure (or use a public TURN server, which means trusting a third party with your traffic). This is the right approach for a general-purpose P2P system, but it's heavy machinery for rmail's simple use case.

### Reverse proxy on a VPS

Run a small VPS (DigitalOcean, Vultr, Hetzner — $4-5/month). Set up a reverse proxy (nginx, caddy) that forwards traffic to your rmail daemon via an SSH tunnel or VPN. Your contacts point at the VPS, the VPS forwards to you.

This gives you: a stable public IP, no router configuration, TLS termination if you want it. It costs money, but it's the most reliable option for someone who can't configure their router.


## Part 7: What rmail does

Given all of the above, here's the design:

### auto_port_forward config option

```lua
# in ~/.config/rmail/config
auto_port_forward = false    -- default: OFF
```

When enabled, rmail will attempt automatic port forwarding at startup:

1. Try UPnP (via `upnpc`) — most widely supported
2. If UPnP fails, try NAT-PMP (via `natpmpc`)
3. If both fail, log a warning and continue without a mapping

The mapping is created for the port specified in the contacts file (`me.port`). It maps external port -> internal port (same number).

### Mapping lifecycle

- **Creation:** At startup, after binding the listening socket
- **Renewal:** Every 30 minutes (for NAT-PMP, which has lifetimes; UPnP mappings are requested as permanent)
- **Cleanup on next startup:** Lua can't reliably catch SIGTERM (the `os.signal` ecosystem is fragile and non-portable). So instead, rmail writes the current mapping details to a state file (`STATE/nat_mapping.json`). On the next startup, it reads this file and deletes the old mapping before creating a new one. If the daemon crashes and is never restarted, the NAT-PMP mapping expires on its own; UPnP mappings stick around (but get overwritten on next startup since we use the same port).

```json
{
  "protocol": "upnp",
  "external_port": 8025,
  "internal_port": 8025,
  "created": 1700000000
}
```

### Security check: UPnP/NAT-PMP detection

This is the more important feature. On every startup, regardless of the `auto_port_forward` setting, rmail probes for UPnP and NAT-PMP on the local network:

1. Send an SSDP discovery multicast (UPnP)
2. Send a NAT-PMP external address request to the default gateway

If either responds, it means the router has these protocols enabled. This is a security concern even if rmail isn't using them — any other device or malware on the LAN can. So rmail:

- Logs a warning: "UPnP is enabled on your router. Any device on your LAN can open ports. Consider disabling it."
- Notifies contacts (via a one-time advisory message) so they know your network configuration

The security check runs on every startup and cannot be disabled. It uses a one-time warning file to avoid repeatedly notifying contacts.


## Part 8: Recommendations

### For most users: manual port forwarding

Disable UPnP and NAT-PMP on your router. Set up a manual port forward for rmail's port. This is the safest configuration.

Disabling UPnP/NAT-PMP protects not just rmail but your entire network. Those protocols are a liability — they existed before IoT filled our networks with devices of questionable security. Every security guide published in the last decade recommends disabling them.

### For users who can't access their router

Maybe you're on a shared network, or your ISP manages the router, or you just don't have the admin password. This is what `auto_port_forward` exists for. It's a convenience escape hatch. It works, it's widely compatible, and the risk is bounded — you're only opening the one port rmail uses.

But understand what you're enabling: if UPnP/NAT-PMP isn't already active on the router, `auto_port_forward` won't work (rmail doesn't enable them on the router, it only uses them if they're already on). If they ARE already active, any device on the LAN could already be exploiting them. rmail using them too doesn't make things worse.

### The security check exists for awareness

The UPnP/NAT-PMP detection on startup isn't about rmail specifically. It's about making sure you know the state of your network. If you're running a peer-to-peer messaging daemon, you probably care about security. The check exists so you can't accidentally run on a network with these protocols enabled without knowing about it. Think of it as a network hygiene audit that happens to run at startup.

### If you want the best security

Use a VPN (Tailscale is the easiest), or set up an SSH tunnel to a VPS. No port forwarding needed at all — NAT stops being a problem because you're not accepting inbound connections through it. Your router's firewall stays intact. The only downside is the dependency on external infrastructure (a VPN coordination server, or a VPS you pay for). For a personal messaging system, this is probably overkill. But it's the right answer if your threat model includes adversaries on your LAN.


## Summary of protocols

| Protocol | Auth | Transport | Complexity | Router support | Verdict |
|----------|------|-----------|------------|----------------|---------|
| UPnP IGD | None | SSDP + SOAP/HTTP | High (XML everywhere) | Very high (~80% of consumer routers) | Works but insecure |
| UPnP Device Protection | TLS + ACLs | SSDP + SOAP/HTTPS | Very high | Near zero | Dead spec |
| NAT-PMP | None | UDP binary | Low (12-byte requests) | Medium (Apple routers, some others) | Cleaner than UPnP, same trust model |
| PCP | None (RFC 7652 exists but unimplemented) | UDP binary | Medium | Low-medium (growing) | Best design, still no real auth |
| Manual forwarding | Router admin password | N/A | N/A | Universal | Gold standard |

The pattern is clear: the protocols that exist and work have no authentication. The authentication extensions that exist don't work (no implementations). This isn't going to change — the industry has moved on to VPNs and relay-based solutions rather than fixing NAT traversal protocols.
