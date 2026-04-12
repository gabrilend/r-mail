# Missed IP update: contacts go stale when offline during IP change

## The problem

When you change routers (or your ISP reassigns your IP), rmail sends
`POST /update-address` to all your contacts. But if a contact's server is
offline at that moment, they never learn your new IP. You're now unreachable
to them.

Worse: if they also change IPs while you're offline, neither side knows how
to reach the other. The connection is severed permanently. The only recovery
would be both returning to their old IPs simultaneously — which is unlikely,
especially if an ISP reassigned the address.

## Why this is hard

rmail's design is fully peer-to-peer with no central infrastructure. There's
no relay, no registry, no rendezvous server. Each daemon only knows its
contacts' last-known IPs. If both sides lose track of each other, there's no
third party to ask.

## Partial mitigations (none fully solve it)

### DNS (issue #311)
If both sides use dynamic DNS, they can always resolve each other's hostname.
This solves the problem for users who set up DDNS. But it introduces a
dependency on a third-party DNS provider.

### Retry with exponential backoff
When a contact is unreachable, keep retrying the IP update at increasing
intervals. If their server was just temporarily down, this catches them
when they come back. Doesn't help if their IP also changed.

Open question: from the retrying side, how do we distinguish "they're
briefly offline" from "their IP changed and they're now elsewhere"? We
can't, without another signal. Pragmatically we retry either way — the
retry is cheap and handles the common case.

### Mutual contact recovery via known third party
If Alice and Bob lose each other, but both still know Carol, Carol could
broker a reconnection. Carol knows both their current IPs. This requires
a protocol extension and trust model.

**Rejected:** Carol would learn that Alice and Bob are contacts. That's
a breach of the privacy guarantee we make — contact relationships should
stay private to the two parties.

### Cache and prefer IPv6
Whenever a connection succeeds over IPv4, cache the peer's IPv6 address
(if reachable) and prefer it on future connections. This doesn't *solve*
the stale-contact problem, but an IPv6 address is far more stable than a
router's public IPv4 — ISPs rarely renumber IPv6 allocations, so it
shrinks the window where a contact can go stale. See #304 for broader
IPv6 support.

### Last-resort broadcast / scan
Brute-force: scan common port ranges. Completely impractical at internet
scale. Could work on a LAN.

### Store-and-forward via a relay (rejected)
A minimal relay server that holds encrypted IP-update messages. Each
user checks the relay periodically. **Rejected:** contradicts rmail's
no-central-infrastructure design. Not considered further, even opt-in.

### Sneakernet / out-of-band
Users manually share their new IP through another channel (text message,
phone call, in person). Always works. Not automated.

## What we know for sure

- DNS is the cleanest fix for users willing to set it up
- The retry-on-failure approach should be implemented regardless — it
  handles the common case (contact was just offline briefly)
- The "both sides change simultaneously" scenario has no clean peer-to-peer
  solution without some form of rendezvous

## Speculative: rendezvous via in-transit packets

Can two isolated peers re-find each other using only the infrastructure
their packets are already passing through (ISPs, maybe CDNs)?

The shape of the idea: each side emits packets that "circulate" and
carry a shared token (effectively a password). When two such packets
meet somewhere in transit, they recognise each other and report the
current endpoints back to their senders. A kind of hunting heuristic
run on infrastructure we don't own.

Open questions before this is worth any more thought:

- What processing is actually available at ISPs / peering points /
  CDNs? Can any of it be driven by a third party?
- Does ISP behaviour vary enough between providers that a general
  mechanism is unworkable?
- Are there transformations applied to packets en route that we could
  exploit (or that would foil this)?
- What's the minimum set of third parties we're depending on? ISP is
  unavoidable; CDN and DNS are optional — is there a design that
  avoids CDN entirely?
- How do we avoid flooding the network when multiple pairs are
  "hunting" at once?

This is at the back-of-a-napkin stage. Park it until someone can answer
at least the first two questions.

## Status

Open problem. No known complete fix within rmail's design constraints.
Collecting ideas.
