# #402 — When our address changes, every contact is told

## Status

Completed — a blueprint written 2026-10-04 (#621) for what was built
before issue files described it.  The mechanism #403, #404, #409 and
#410 refine.

## Current Behavior

A contact reaches us at the address in their contacts file.  When our
public address changes — a home connection's address is often reassigned
— that entry goes stale, and only we can tell them.  So the daemon
watches its own address and announces it.

**Knowing our address** (#401): at start-up and then every 24 to 48
hours, at a time drawn at random each time so it wanders through the day
(#410), the daemon asks DNS-based services what its public IPv4
address is, and its LAN and IPv6 addresses from the system; they are kept
in `.state/public_ip`, `lan_ip`, `public_ipv6`.  A change of public
address is believed only when a second, different provider confirms it.
The first address ever seen is just recorded.

**Owing an announcement.**  A confirmed change queues one announcement
per contact that has an address (`.state/pending-address.json`: contact
-> address).  So does every start-up, unprompted (#115): a restart is a
repair, because a contact whose entry for us went stale has no way to
ask.

**Announcing** (each cycle, #112):
`POST /update-address {ip, port, ips, local_ips}`.  `ips` is our whole
public set — a configured `hostname` first, then the public IPv4, then
IPv6 (#409); `local_ips` (our LAN address) goes only to a contact on our
own LAN, since anywhere else a private address names some other device.
The set is computed when sent, not when queued, so a queued announcement
that sat through another change says where we are now.  Each is retried
until the contact answers.

**Receiving one.**  The sender's set replaces what we had for them: a
pinned default `ip` stays first, the rest are merged; a private address
is kept only if it is on our own /24, filed as `local-ip`; a contact
kept under a hostname keeps it (DNS already follows their changes, #405).
The contacts file is rewritten only if the set really changed — an
announcement that says nothing new writes nothing and sends nothing back,
which is what stops two idle daemons from announcing to each other
forever.  A real change leaves a hidden note (`inbox/.address-update-<name>`)
that queues our own announcement to them, as a test of the new address;
the first request that reaches them there removes the note.

## Intended Behavior

As above.

## Suggested Implementation Steps

1. `rmail.lua`: `check_public_ip`, `verify_ip_change`, `detect_ip_change`,
   `detect_ipv6_change`, `check_lan_ip_change`; the start-up queueing in
   `init_runtime`; `sync_address_notifications`; `addrset.mine`;
   `handle_update_address`, `addrset.merge`, `addrset.write`,
   `addrset.write_local`; the note's removal in `run_sync_cycle`; `addrchk`
   (the daily re-check).
2. Tests: `scripts/test-lan-address-learning.sh`; the two-mailbox tests
   exercise the start-up announcement.

## Related documents

- `docs/.templates/ports-explained.md`, `docs/.templates/nat-traversal-report.md`
- `#404`, `#405`, `#403`, `#401`, `#115`, `#410`, `#409`
