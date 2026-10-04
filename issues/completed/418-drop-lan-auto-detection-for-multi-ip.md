# #418 — Drop LAN auto-detection and the unused /peer-address endpoint

## Current Behavior

Complete 2026-10-04.  The daemon finds no addresses on its own any more.
A contact's home-network address is its `local-ip` line (#409), written
by hand or announced by a mailbox that already has one, and the ordinary
address list (`contact_endpoints`) tries it first whenever it shares our
network.  Gone:

- **LAN discovery**: the multicast group, the scan of all 254 home
  addresses (at startup and after a failed connection), the replies, the
  UDP socket the daemon opened on its own port, and the packet encryption
  only discovery used.  The daemon listens on TCP only.
- **The same-house swap** (`do_resolve_lan_host`): a request to our own
  public address redirected to the contact's local address.
- **Addresses learned from incoming connections** (`rt.lan.peers`, and the
  "relayed" note beside it), held in memory until restart.
- **The cached hostname lookup** (`resolve_contact_host`, `dns_cache`),
  which only the swap used.
- **`/peer-address`**, the `allow_peer_address_requests` setting, and the
  phone's uncalled `getPeerAddress`.
- `scripts/test-lan-discovery-names.sh` and
  `scripts/test-lan-address-learning.sh`, with what they tested.

Old `name.lan_ip` contact lines are rewritten as `local-ip` lines on load
(`migrate_lan_ip_lines`, marked DEPRECATED).  Kept, on purpose: the
`lan_ip` key in `/api/myaddress`, because the phone reads it (see "What
to remove", item 4).

Found and fixed on the way, because the swap had been hiding it: this
machine's own home-network address was recorded as 127.0.0.1, so the
ordinary address list never judged a same-house contact to be on our
network (see #410's follow-up of 2026-10-04).

Tested by `scripts/test-home-address.sh` (the loopback record, the
`lan_ip` rewrite, no UDP or discovery) and
`scripts/test-local-ip-delivery.sh` (two mailboxes in one house deliver
by their `local-ip` lines alone).

## Intended Behavior

#408 shipped per-contact multi-IP (`ip[N]`/`port[N]`) plus Phase 2
connection-failure fallback plus Phase 3 address-promotion, and #409
added `local-ip` for home-network addresses.  Together they cover what
the "LAN IP detection / same-network optimisation" machinery did, so
that machinery is removed wholesale.  While in the address-plumbing code,
`/peer-address` and `allow_peer_address_requests` go too: the endpoint
was exposed by the daemon and had a stub in the Android client
(`RmailClient.getPeerAddress`), but nothing called it and no completed
issue specified it.

## Why this is worth doing

The LAN machinery was five loosely-connected features
(`nat.get_local_ip`, `do_resolve_lan_host`, UDP LAN discovery,
`c.lan_ip` field, `/whoami`'s `lan_ip` reply field) that together
answered one question: *"is this contact reachable on my LAN without
leaving the router?"*

After #408 and #409, the user expresses the same thing directly in
`contacts`:

```
alice.ip       = wan.alice.example        # default
alice.port     = 8025
alice.local-ip = 192.168.0.5              # tried first, on our own network
```

- On home wifi: the local address shares our /24, so it is tried first.
- On foreign wifi: it does not share our /24, so it is not tried at all
  (private addresses name some other device elsewhere); the public
  address is.

No subnet-scan or multicast packets, no implicit substitution that is
hard to reason about.

## Further reasons found 2026-10-04

**The owner rules out multicast:** "I don't think we should allow
multicast groups, because they break the security model. If multiple
people can listen on a network, then a compromised system could listen
to that multicast address without 'claiming' the port number with the
OS, who then receives it from the router and only the router. The
router has to send one port to exactly one address, always."  The
subnet scan breaks the same rule a different way: it sends the same
packet to all 254 addresses on the local network, so every device there
receives it.  The packets are encrypted with the contact's token, but
their arrival still tells every listener that an rmail mailbox is at the
sending address, on which port, and when it syncs.

**And the machinery did not work as it stood:**

- A daemon started at boot, before the network is up, failed to join the
  multicast group and never tried again.  Both mailboxes on the owner's
  machine logged "failed to join multicast group" at 06:40:23 on
  2026-10-04.
- The discovery socket was not among the things the main loop waits on.
  It was read only at the start of a sync round, so a neighbour's "are
  you here?" waited for the next round, which is minutes once a contact
  has backed off (per-contact timers, #115).
- A firewall that drops incoming traffic except named ports drops a
  machine's own multicast packet when it loops back, because the
  packet comes back in through the network card rather than loopback.
  This is why `scripts/test-lan-discovery-names.sh` failed on the
  owner's machine (firewall written 2026-10-03; test ports 59391/59392).
- At boot the two mailboxes exchanged about 1,500 "is at 127.0.0.1"
  discovery lines in three seconds, every one wrong.

## Accepted regression: zero-config LAN discovery

Two rmail users on the same LAN who exchanged contact info with public
addresses only no longer pick up each other's LAN addresses on their
own.  One of them writes `alice.local-ip = 192.168.0.5` by hand; from
then on announcements carry it both ways (#409 sends local addresses to
a contact already known to be on our network).

That's fine.  LAN addresses are static-ish (DHCP reservation is already
recommended in the docs for router-port-forwarding stability), and the
one-time edit is cheap compared to keeping the discovery machinery
running.  Owner, 2026-10-04, on the learning and the swap: "let's delete
these for now since we don't need them."

## What to remove

1. **`do_resolve_lan_host` + `lan_peers` in-memory cache**, and the
   learning from incoming connections that filled it.  Removed.
2. **UDP LAN Discovery.**  `send_lan_discovery` (multicast + subnet
   sweep), `handle_udp_discovery`, `poll_udp_discovery`,
   `do_on_connection_timeout`, the multicast group join, the UDP socket,
   `encrypt_packet` / `decrypt_packet`.  Removed; the daemon speaks no
   UDP of its own except its outgoing DNS lookups.
3. **`c.lan_ip` as a contact field.**  Rewritten on load as `local-ip`
   (see "Transition").  `load_contacts` still folds a `lan_ip` value in
   as one more local address, so a file not yet rewritten keeps working.
4. **`lan_ip` key in `/api/myaddress`** — **kept** (decided 2026-10-04).
   This issue first said nothing else reads it.  The phone does: it
   stores the home computer's local address from that reply
   (`MainViewModel.fetchMyAddress` → `serverLanIp`) and offers it to
   `HostPicker`, which tries it first on the home network.  Removing it
   would take that away from the phone; the owner's approval was given
   on the understanding that the field was unused.
5. **`/peer-address` endpoint** (`handle_peer_address`), its dispatch
   case, the `allow_peer_address_requests` setting, and the phone's
   `getPeerAddress`.  Removed.

## What to keep

- **`nat.get_local_ip()`** — used by the port-forwarding helpers
  (`nat.try_upnp_add`, `try_auto_port_forward`), by
  `check_lan_ip_change`, and by `/api/myaddress`.  Now answers only from
  the routing table and never with a loopback address (#410 follow-up).
- **`check_lan_ip_change` + `.state/lan_ip`.**  Watches whether *this
  host's* LAN address changed and warns that the router's port-forward
  now points at the wrong machine; also the "our network" that
  `contact_endpoints` and the announcements compare against.
- **Hostname support in `ip`/`ip[N]` fields.**  Resolved at each
  connection by the socket library.
- **`/update-address`** (`handle_update_address`), the address-change
  notification.

## Transition for existing `c.lan_ip` values

`migrate_lan_ip_lines`, run first in `align_contacts` (startup and every
contacts change), rewrites each `name.lan_ip = X` line.  Three paths: no
plain `local-ip` line yet — it becomes `name.local-ip = X`; a local-ip
already holding X — the old line is dropped as a duplicate; a local-ip
holding something else — it becomes the next `name.local-ip[N]`.  Each
is logged.  Idempotent: a rewritten file has no `lan_ip` lines left.

**Deprecated at birth.**  It carries a `DEPRECATED(#418)` comment, and
is deleted once `lan_ip` is presumed extinct; that removal gets its own
issue then.

## Suggested Implementation Steps

1. `rmail.lua`: delete the discovery block (multicast address, join,
   send, handle, poll, the connection-timeout hook and its call), the
   UDP socket in `init_runtime` and its poll before each sync round, the
   startup discovery send, and `encrypt_packet` / `decrypt_packet`.  The
   "listening on" line says TCP only.
2. `rmail.lua`: delete `do_resolve_lan_host`, the `resolve_lan_host`
   hook and its use in `http_post_batch`, the learning block in
   `handle_request`, `rt.lan`, and `resolve_contact_host` with
   `dns_cache` (and the two places that cleared the cache).
3. `rmail.lua`: delete `handle_peer_address`, its dispatch case and
   `cfg.allow_peer_addr`; Android `RmailClient.getPeerAddress`.
4. `rmail.lua`: `migrate_lan_ip_lines` in `align_contacts`.
5. Tests: delete `test-lan-discovery-names.sh` and
   `test-lan-address-learning.sh`; add `test-home-address.sh` and
   `test-local-ip-delivery.sh`; the phase 4 demo runs the new two.
6. Docs: README (one TCP port; no `allow_peer_address_requests`),
   protocol guide (no `/peer-address`), ports guide (`local-ip` for a
   same-house contact), `q-a-tests.md`; notes on #415, #416, #417 that
   they were removed, and on #409, #419, #506, #826 where they mentioned
   what went.

## Other simplification candidates (separate issues, not this one)

- The legacy `c.ipv6` field — already marked `DEPRECATED(#408)` in
  the code.  Drop once every config has rolled over.
- `contact_addr(c)` — still used for logs / UI summaries.  Narrow
  enough to inline as `contact_hosts(c)[1]`, but low priority.

## Source

Raised 2026-04-17 during #408 QA setup.  User observation: if we can
list extra IPs/ports per contact, the auto-detection layer's purpose
is covered by explicit config.  Subsequent grep turned up
`/peer-address` as similarly under-used and it got folded into the
same cleanup.  Built 2026-10-04 after the owner's question "what are
discovery packets? Why do we need them?" and the answer that `local-ip`
lines had replaced them.

## Status

Complete 2026-10-04.

**Revised by #409 (2026-09-22):** a separate `local-ip` field was added,
reversing "LAN addresses go in `ip[N]`".  Addresses are *announced* and
written into other people's contacts files by the daemon, so the daemon
must know which addresses are LAN-only — a remote contact holding our
192.168.x.x in `ip[N]` would try it on its own network and reach some
other device.  So the migration target is `local-ip`.  The /24 same-LAN
check this needs is the kind of subnet guessing this issue wanted gone —
accepted, because it errs toward not trying.
