# #347 — Multiple IPs per contact with auto-reordering and unified address type

## Problem

A contact currently has a single `.ip` field. That's brittle: if the
contact has both a LAN and WAN address, or a DDNS hostname as a fallback,
or a stable IPv6 alongside a changing IPv4, we can only pick one.

## Desired behavior

### Multiple IPs per contact

A contact can have more than one `ip` line in the config file. The daemon
tries each one in the order they appear until a connection succeeds.

```
alice.ip = 123.45.67.8
alice.ip = alice.duckdns.org
alice.ip = 2001:db8::1
alice.token = "..."
```

### Auto-grouping on load

If the same contact has `ip` entries scattered throughout the config, the
daemon re-writes the config so all of a contact's lines are contiguous.
Example:

```
# before
alice.ip = 123.45.67.8

... some stuff

bob.ip = 9.8.7.6
bob.token = "..."

... more stuff

alice.ip = 98.76.54.32
```

Becomes:

```
# after
alice.ip = 123.45.67.8
alice.ip = 98.76.54.32

... some stuff

bob.ip = 9.8.7.6
bob.token = "..."

... more stuff
```

### Unified address type

A single `ip` field accepts IPv4, IPv6, or a DNS hostname — the daemon
detects which by parsing. No separate `ip`, `ipv6`, `hostname` fields.

Overlaps with #311 (DNS hostnames in contacts) on the hostname-detection
and resolution plumbing. #311 handles the case where `ip` *is* a hostname;
this issue generalises to "n addresses of mixed type" on top of that.

### Stretch: promote the winning address

When the daemon connects, if the address that succeeds is not the first
one in the list, move it to the top of that contact's block on disk. The
fast path for future connections then matches reality.

## Source

From `issues/new-issue-todo`.

## Status

**Phase 1 complete.**

Landed in this pass:

- **Schema: multiple `ip` lines per contact.** `load_contacts` collects
  every `name.ip = ...` line into `contact.ips` (a list). The first
  one also lives at `contact.ip`, so every existing consumer of
  `contact.ip` and `contact_addr()` keeps working unchanged. A legacy
  `.ipv6` field is folded into the same list.
- **New helper `contact_hosts(contact)`** returning the address list
  in preferred order. Ready for Phase 2 to walk on connection
  failure.
- **Auto-grouping in `align_contacts`.** Scattered `name.*` lines are
  now consolidated at the contact's first position (verified against
  the example in this issue). The existing `=` alignment still runs
  afterwards on the now-contiguous blocks.
- **`handle_update_address` guard:** if the contact has more than one
  IP configured, an inbound single-address update no longer clobbers
  the list. Port updates still apply.

Deferred (separate follow-ups):

- **Phase 2: retry on connection failure.** The sender needs to walk
  `contact_hosts(c)` when the first address can't be reached. This
  touches every `http_post_batch` call site that currently passes
  `host = contact_addr(c)` — sync_outbox, send_consent_responses,
  send_attachment_cancellations, sync_inbox delete notify,
  update-address push, and the LAN-discovery / peer-address probes.
  Simplest implementation sketch: after the initial parallel dispatch,
  retry each failure individually with subsequent addresses from the
  list (no change to `http_post_batch`'s state machine, slight loss
  of parallelism only on the fallback path). Without Phase 2, users
  can **declare** multiple IPs and they'll **survive** auto-grouping,
  but only the first is tried today.
- **Phase 3 (stretch): promote the winning address.** When a non-first
  address succeeds, rewrite the contacts file so that address is first
  for future connections. Needs a multi-value-aware write path —
  `write_contact_fields` currently assumes one value per field.

Re-open or spawn new issues for Phase 2 and Phase 3 when ready to
implement.
