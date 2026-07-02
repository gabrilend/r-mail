# #365 — Drop LAN auto-detection and the unused /peer-address endpoint

## Summary

#347 shipped per-contact multi-IP (`ip[N]`/`port[N]`) plus Phase 2
connection-failure fallback plus Phase 3 address-promotion.  The
combination subsumes what the pre-#347 "LAN IP detection /
same-network optimisation" machinery did, so we can remove that
machinery wholesale.  While we're in the address-plumbing code we
should also drop `/peer-address` and `allow_peer_address_requests`:
the endpoint is exposed by the daemon and has a stub in the Android
client (`RmailClient.getPeerAddress`), but nothing actually calls it
and no completed issue specifies it — it's dead code that implies a
feature that isn't wired up.

## Why this is worth doing

The current LAN machinery is five loosely-connected features
(`nat.get_local_ip`, `do_resolve_lan_host`, UDP LAN discovery,
`c.lan_ip` field, `/whoami`'s `lan_ip` reply field) that together
answer one question: *"is this contact reachable on my LAN without
leaving the router?"*

After #347, the user expresses the same thing directly in
`contacts`:

```
alice.ip       = wan.alice.example        # default, tried first
alice.port     = 8025
alice.ip[1]    = 192.168.0.5              # LAN, fallback
```

- On home wifi: LAN entry succeeds → promotion moves it to default
  slot → subsequent cycles hit LAN first.
- On foreign wifi: LAN entry fails → fallback walks to next entry →
  WAN entry succeeds → promotion moves it up.
- Back home: LAN fails (wrong subnet), WAN succeeds (hairpin NAT or
  not), then LAN succeeds on next cycle and gets promoted back.

Self-healing across network moves, no subnet-scan multicast packets,
no implicit "magic" substitution that's hard to reason about.

## Accepted regression: zero-config LAN discovery

Pre-#347, two rmail users on the same LAN who exchanged contact info
over rmail (WAN IP only) would automatically pick up each other's
LAN IPs via UDP discovery.  Post-#365 they'll need to add
`alice.ip[1] = 192.168.0.5` by hand.

That's fine.  LAN IPs are static-ish (DHCP reservation is already
recommended in the docs for router-port-forwarding stability), and
the one-time edit is cheap compared to the complexity of keeping the
discovery machinery running.  No `/whoami` write-back mitigation — we
accept the regression and keep the daemon simpler.

## What to remove

1. **`do_resolve_lan_host` + `lan_peers` in-memory cache.**  The
   entire "if this contact's public IP == my public IP, swap for
   their LAN IP" code path.  Replaced by explicit `ip[N]` entries.
2. **UDP LAN Discovery.**  `send_lan_discovery` (multicast + subnet
   sweep), `handle_udp_discovery`, `poll_udp_discovery`, and the
   multicast group bind.  The daemon stops speaking UDP entirely
   once this lands.
3. **`c.lan_ip` as a special-case contact field.**  Migrate any
   existing values into `ip[N]` (see "Transition" below) and stop
   reading the field anywhere.
4. **`lan_ip` key in the `/whoami` (`/api/myaddress`) response.**
   Only useful today as an input to (1) and (2); nothing else reads
   it.
5. **`/peer-address` endpoint** in the daemon
   (`handle_peer_address`), its routing dispatch in the HTTP handler,
   the `allow_peer_address_requests` config flag, and the
   `getPeerAddress` stub in `clients/android/.../RmailClient.kt`.
   No live caller exists; the feature it hints at (verify my
   address is current on the peer) would in practice be covered by
   `/update-address` being idempotent.

## What to keep

- **`nat.get_local_ip()`** — still used by port-forwarding helpers
  (`nat.try_upnp_add`, `try_auto_port_forward`) and by
  `check_lan_ip_change`.
- **`check_lan_ip_change` + `.state/lan_ip`.**  Watches whether
  *this host's* LAN IP changed between runs and warns the user that
  their router's port-forwarding rule now points at the wrong
  machine.  Unrelated to contact resolution; belongs to the
  port-forwarding story.
- **Hostname support in `ip`/`ip[N]` fields.**  Independent of LAN
  detection.
- **`/update-address`** (`handle_update_address`).  This is the
  actual IP-change-notification mechanism; it's well-exercised and
  stays.

## Transition for existing `c.lan_ip` values

Users who already set `alice.lan_ip = 192.168.0.5` in their contacts
file shouldn't have to hand-edit it on upgrade.  In `align_contacts`
(the rewriter that already handles Phase-3 promotion and scattered-
line regrouping), add a one-shot migration: any `name.lan_ip = X`
line encountered on load is rewritten as `name.ip[N] = X` (next
available index) on the next save, and the `lan_ip` line is dropped.
Idempotent — once the file is already migrated, subsequent loads are
a no-op.

**This migration is deprecated-at-birth.**  It exists only to spare
users a manual edit across this version boundary.  The code block
should carry a `DEPRECATED(#365)` comment stating it's a transitional
shim and should be deleted after a reasonable rollover window (a
couple of releases, or once the `lan_ip` field is presumed extinct in
the wild).  Track its removal as a follow-up issue once #365's other
phases are in.

## Phases

1. **Phase 1 — migrate `c.lan_ip` and stop reading it.**
   - Add the `lan_ip` → `ip[N]` rewrite to `align_contacts`.
   - Remove the `c.lan_ip` read path in `do_resolve_lan_host` (leave
     the `lan_peers` path temporarily so UDP discovery still works
     for people who haven't restarted yet).
   - Keep `/whoami` returning `lan_ip` for one release so any mid-
     upgrade peers continue to work.
2. **Phase 2 — delete the machinery.**
   - Remove `do_resolve_lan_host`, `lan_peers`, `send_lan_discovery`,
     `handle_udp_discovery`, `poll_udp_discovery`, multicast
     constants, and the UDP socket bind/poll in `main()`.
   - Remove the `lan_ip` key from `/whoami` responses.
   - Remove `handle_peer_address`, its HTTP-dispatch case, the
     `allow_peer_address_requests` config flag and its `cfg.allow_peer_addr`
     reader, and the Android `getPeerAddress` stub.
   - Remove related log lines ("same-network: using LAN IP …", "LAN
     discovery: …", "joined multicast group …").
3. **Phase 3 — housekeeping.**
   - Update `docs/` for the config changes (no more `lan_ip`, no more
     `allow_peer_address_requests`).
   - Update `q-a-tests.md`: remove tests that reference these
     features.
   - Sanity-check that `notify_ip_change` + `/update-address` still
     handle IP changes correctly on their own.

## Other simplification candidates (separate issues, not this one)

- The legacy `c.ipv6` field — already marked `DEPRECATED(#347)` in
  the code.  Drop once every config has rolled over.
- `contact_addr(c)` — still used for logs / UI summaries.  Narrow
  enough to inline as `contact_hosts(c)[1]`, but low priority.

## Source

Raised 2026-04-17 during #347 QA setup.  User observation: if we can
list extra IPs/ports per contact, the auto-detection layer's purpose
is covered by explicit config.  Subsequent grep turned up
`/peer-address` as similarly under-used and it got folded into the
same cleanup.

## Status

Open.  Not blocking #347 QA; file-only for now.
