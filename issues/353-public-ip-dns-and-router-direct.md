# Additional public-IP discovery paths: DNS-based and router-direct

## Background

The daemon discovers its own public IP by HTTP-fetching a small set of
"what is my IP" services (see `IP_SERVICES` in `rmail.lua`).  The list
was recently expanded from 4 to 8 entries and iteration was randomised
so traffic spreads across providers.  Two additional discovery paths
exist that aren't yet wired up.

## Path 1: ask the router directly (UPnP / NAT-PMP)

UPnP exposes `GetExternalIPAddress` and NAT-PMP has a standard
public-address query.  Both miniupnpc and natpmpc are already shipped
with rmail (for port forwarding) and support these calls.

**Pros:**
- Works offline from the WAN's perspective (no third-party service
  traffic).
- Faster than an HTTP round-trip to an external host.
- No dependency on an internet service being up.

**Cons:**
- Many users disable UPnP/NAT-PMP because those protocols let any LAN
  device open ports without auth (rmail already warns about this).
  When disabled, the router API isn't reachable.
- **CGNAT / double NAT.**  ISPs that put subscribers behind a second
  layer of NAT return the customer-premise router's "external" IP,
  which is itself a private/shared address (`100.64.x.x` CGNAT range,
  or another RFC1918 block).  That IP isn't what contacts on the
  public internet can reach.  External HTTP services return what the
  internet actually sees.
- Router quirks: some report `0.0.0.0`, some return the wrong NIC,
  some don't implement the call.

**Suggested integration:** fast path — try the router first, then sanity
check the result.  If it's a public-looking IP (not RFC1918, not CGNAT
range, not link-local), use it.  Otherwise fall back to HTTP services.
Skip entirely if UPnP/NAT-PMP are disabled in config.

## Path 2: DNS-based IP reporting

Several public resolvers answer a special query with the client's
observed source IP:

- **OpenDNS:** `dig +short myip.opendns.com @resolver1.opendns.com`
  (A record — simplest)
- **Google:** `dig TXT o-o.myaddr.l.google.com @ns1.google.com +short`
  (TXT record)
- **Cloudflare:** `dig TXT whoami.cloudflare @1.0.0.1 +short`
  (TXT record)
- **Akamai:** `dig TXT whoami.akamai.net @ns1-1.akamaitech.net +short`

**Pros:**
- Massively faster than HTTP (UDP round-trip on port 53, often a few ms).
- Zero HTML/JSON parsing.
- Port 53 is rarely blocked even on restrictive networks.
- Very cheap for the provider; they're happy to serve it.

**Cons:**
- Luasocket's `socket.dns.toip()` uses the *system* resolver — you
  can't point it at a specific server.  Implementing these queries
  requires crafting raw DNS packets (58-byte A-query format is simple,
  TXT parsing is slightly more work).
- IPv6-only hosts can use dual-stack variants (`myip6.opendns.com`,
  `@resolver1.ipv6-sandbox.opendns.com`).
- Per-network policies: some corporate networks force DNS through a
  proxy that rewrites results; this path would then return the proxy's
  IP, not the user's.

**Suggested integration:** add a `RAW_DNS` fallback list alongside the
HTTP services.  Write a tiny DNS client (A-query + TXT-query builders,
UDP socket, 2–3 second timeout).  Try one random DNS source first; fall
back to HTTP if it fails.  The A-query path (OpenDNS) is the easiest to
implement and probably sufficient.

## Status

Not started.  Filed for visibility after a discussion about expanding
the IP-discovery surface.  Current behaviour (randomised HTTP poll of
8 services with cross-service verification) is already resilient; these
are optimisations, not fixes.
