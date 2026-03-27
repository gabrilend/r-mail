# IP recovery when both sides change simultaneously

## Problem

If two contacts both go offline and reconnect on different networks (new IPs)
at roughly the same time, neither can find the other. The address change
notification goes to the old IP, which is now wrong. There is no automatic
recovery path.

## Constraints

- No trusted third parties (no DNS servers, no relay servers, no bulletin boards)
- No shared infrastructure — must work with only the two rmail daemons
- Must be encrypted (probes use the shared token)
- Must work without both sides being online at the same time

## Approaches considered

### Subnet scan (preferred, needs feasibility study)

On IP change, if a contact doesn't respond at their known IP:
1. Scan their last-known /16 subnet (~65K addresses) on their known port
2. Each probe is a single encrypted packet to one specific port — not a
   traditional port scan
3. Only the real contact can decrypt and respond
4. If found, exchange new IPs

**Advantages:**
- Trustless, encrypted, no third party
- One port per IP is barely a scan — unlikely to trigger security tools
- Practical time: ~65K probes at reasonable rate = under a minute

**Concerns:**
- If the contact is offline during the scan, we miss them
- ISPs don't guarantee IPs stay in the same /16 range
- Different network entirely (home vs coffee shop vs mobile) = different ISP,
  different range — /16 scan is useless
- Intermittent connections make timing unreliable
- Could be perceived as hostile by network monitoring (even if it's one
  port per IP)

**Open questions:**
- How do fail2ban and similar systems handle a single connection attempt to
  one port? Probably fine — fail2ban triggers on repeated failed auth to the
  SAME host, not single probes across hosts.
- What's the realistic range to scan? /16 is optimistic if they changed ISPs.
  /8 is 16 million addresses — maybe 5 hours at 1000/sec.
- Could we use the IP geolocation of the last known address to narrow the
  scan range?
- Should the scan be continuous/periodic (background) or one-shot?

### Third contact relay

If alice and bob both know charlie, and charlie's IP didn't change, both can
reach charlie. Charlie could relay the new addresses.

**Concerns:**
- Requires trusting charlie with both parties' IP addresses
- Requires that charlie trusts both parties (charlie has both in contacts)
- Adds complexity to the protocol (forwarding mechanism)
- Only works if there IS a mutual contact who didn't move

### Manual recovery

User notices mail stopped flowing, checks their new IP, communicates it out
of band (phone call, text, in person).

**This is the current fallback and always will be.** The question is whether
we can automate recovery for the common cases.

## Key insight

The port is more stable than the IP. The install script generates a random
port, and users are encouraged to keep it constant (changing it means updating
router config + contacts on all peers). So we can trust that the port stays
the same even when the IP changes.

## Possible hybrid approach

1. On IP change, try to notify contacts at their known IP (handles the
   common case where only one side moved)
2. If notification fails, start a background scan of their last-known /16
   on their known port (handles same-ISP case)
3. If scan fails, periodically retry step 1 + step 2 (handles the case
   where the contact comes online later)
4. After N days of failure, drop a note in the user's inbox: "Can't reach
   alice — her IP may have changed. Last known: 184.3.201.206"

The periodic retry handles the "both offline at different times" problem.
The scan handles same-ISP IP reassignment. The manual fallback handles
everything else.

## Status

Research / design phase. Not yet implementing.
