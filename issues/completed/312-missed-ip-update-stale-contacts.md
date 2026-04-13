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

### Retry indefinitely (no backoff)
When a contact is unreachable, keep retrying the IP update at the
regular sync interval — don't back off over time. Exponential backoff
is tempting on paper ("be a good network citizen") but wrong for this
use case: users have legitimate reasons to leave a server off for
weeks or months (vacation, a laptop they only power on when back in
town). A backed-off retry schedule could let messages wait hours,
days, weeks, years before they get through. The retry cost is trivial
— one packet per sync cycle to each unreachable contact — so just
keep at it.

Adjacent idea worth keeping: record a **last-connected timestamp** in
the contacts file per entry. This is purely advisory for the user
("haven't heard from alice in 47 days") and a starting point if we
ever do want to make retry cadence adaptive without being
user-hostile.

Open question: from the retrying side, we still can't distinguish
"they're briefly offline" from "their IP changed and they're now
elsewhere" without another signal. Pragmatically, retry either way —
the retry is cheap and handles both cases transparently the moment
the peer does come back.

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

**This is the only option for the worst case.** Every other
mechanism above either trades away rmail's privacy/no-infrastructure
guarantees (Carol, relay) or only partially closes the window (DNS,
IPv6, indefinite retry). Once both peers have lost each other's
current address with no DNS fallback and both have changed IPs,
there's no purely-peer-to-peer rediscovery that preserves the
design constraints.

## What we know for sure

- DNS is the cleanest fix for users willing to set it up
- Indefinite (non-backoff) retry should be implemented regardless —
  it handles the common case (contact was just offline briefly,
  even for a long "briefly")
- The "both sides change simultaneously and neither uses DNS"
  scenario has **no clean peer-to-peer solution** within rmail's
  design constraints; sneakernet is the honest fallback

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

Closed as **unsolvable** within rmail's stated constraints.

For the worst-case scenario (both peers change IP while neither is
reachable, and neither uses DNS), there is no peer-to-peer
rediscovery that preserves the privacy + no-central-infrastructure
design. Sneakernet is the honest answer.

What this does *not* mean: the near-common-case is unsolved. The
other items in this thread are still worth implementing under their
own issues:

- **DNS hostnames in contacts** — issue #311, already filed.
- **Indefinite (non-backoff) retry** on `/update-address`
  — low-risk, small change.  Open a follow-up issue when this
  moves to implementation.
- **IPv6 caching and preference** — covered by #304.
- **Last-connected timestamp in contacts** — adjacent quality-of-
  life idea; can be a separate issue when someone wants it.

Moved to `completed/` because this issue exists only to capture the
design exploration for the worst case, and that exploration is
done. Partial-mitigation work continues in the issues named above.
