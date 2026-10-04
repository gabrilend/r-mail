# Public-IP discovery via DNS (implemented) and router-direct (rejected)

## Outcome

**DNS-based discovery — implemented.**  rmail.lua now queries three
well-known DNS providers directly over UDP to get its public IP, and
has dropped the HTTP-based service list entirely.

**Router-direct (UPnP / NAT-PMP) — rejected.**  The explicit design goal
is to *not* reward users for leaving insecure NAT protocols on.  Adding
a code path that uses them for public-IP discovery would implicitly
endorse running them, and CGNAT breaks the router-direct result anyway
(the router reports its own CGNAT-side address, not the real public
one).  Kept out of the codebase.

## DNS implementation summary

New in `rmail.lua`:

- `uint16_be` / `parse_uint16_be` / `encode_dns_name` helpers
- `dns_query_public_ip(name, qtype, qclass, resolver_ip)` — sends a
  minimal DNS query over UDP/53 and parses the first A or TXT answer
- `IP_SERVICES` replaced with eight entries across three providers:
  - **OpenDNS** (Cisco) — `myip.opendns.com` A/IN via `208.67.222.222`
    and `208.67.220.220`
  - **Cloudflare** — `whoami.cloudflare` TXT/**CHAOS** via `1.1.1.1`
    and `1.0.0.1`
  - **Google** — `o-o.myaddr.l.google.com` TXT/IN via Google's four
    authoritative nameservers at `216.239.32.10`, `.34.10`, `.36.10`,
    `.38.10`
- `check_public_ip` and `verify_ip_change` iterate a shuffled copy so
  no single resolver is the de facto primary
- `verify_ip_change` deduplicates on **provider**, not resolver — two
  Cloudflare anycast IPs would always agree whether the answer is
  right or wrong; true verification requires a different operator

## Why DNS over HTTP

- Faster: UDP round-trip to a nearby anycast resolver is typically
  5-20 ms vs 50-200 ms for HTTP
- UDP/53 is rarely blocked (breaking it breaks everything)
- No third-party "what's my IP" microservice sees the traffic; the big
  DNS operators already terminate the request by design
- Reduced trust surface: three large, well-known operators instead of
  eight smaller sites

## Cloudflare's CHAOS quirk

`whoami.cloudflare` responds only in DNS class **CHAOS (3)**, not the
standard IN class (1).  CHAOS was originally defined for the MIT CHAOS
network protocol and is now a convention for "metadata about the
resolver itself."  `dns_query_public_ip` takes a `qclass` parameter
for exactly this case; most entries in `IP_SERVICES` use IN.

## Verification

Wire-format tested against all six providers outside rmail: every one
returned the same public IP, confirming the query builder matches real
DNS and the response parser handles both A and TXT records (including
DNS name-compression pointers in the answer's NAME field).

## Status

Closed — DNS discovery implemented, router-direct declined for security
reasons.
