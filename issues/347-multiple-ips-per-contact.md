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

**Phases 1, 2, and 3 complete. Per-IP ports designed, deferred to a
follow-up issue when a user needs it.**

Landed in this pass:

- **Schema: multiple `ip` lines per contact.** `load_contacts` collects
  every `name.ip = ...` line into `contact.ips` (a list). The first
  one also lives at `contact.ip`, marked in a `TODO(#347)` comment as
  a back-compat shim to drop once every call site migrates to
  `contact_hosts()`. A legacy `.ipv6` field is folded into the same
  list, also `DEPRECATED(#347)`-tagged for future removal — users
  can add another `name.ip = <v6-address>` line now that type
  detection handles IPv6.
- **Helper `contact_hosts(contact)`** returning the address list in
  preferred order.
- **Auto-grouping in `align_contacts`.** Scattered `name.*` lines are
  consolidated at the contact's first position (verified against the
  example in this issue). The existing `=` alignment still runs
  afterwards on the now-contiguous blocks.
- **`handle_update_address` guard:** if the contact has more than one
  IP configured, an inbound single-address update no longer clobbers
  the list. Port updates still apply.
- **Retry-on-failure: `http_post_batch_with_fallback`.** Wraps the
  existing parallel `http_post_batch`; the first attempt dispatches
  as before, so the hot path is unchanged. Any request whose result
  has no `status` (connection-level failure, not an HTTP response)
  and whose `hosts` list has more than one entry is retried serially
  against `hosts[2..]` until one succeeds or the list is exhausted.
  HTTP-level errors (404, 500, etc.) are returned as-is — a
  different IP for the same peer won't fix a protocol error.
- **All six `http_post_batch` call sites migrated:**
  `send_consent_responses`, `send_attachment_cancellations`, the
  attachment-chunk sender, `sync_outbox`'s main batch,
  `sync_inbox`'s deletion notifier, and the update-address push.

Phase 3 (this pass):

- **`promote_contact_address(name, addr)`** rewrites the contacts
  file so the winning address lives at the top of that contact's `ip`
  block. Only the `ip` lines are reordered; `port`, `token`, and
  other fields stay in place. No-op when the winner is already
  first, when the contact has fewer than two addresses, when the
  address isn't found, or when the write would produce identical
  content (that last check also keeps the contacts inotify watcher
  from firing spuriously).
- **`http_post_batch_with_fallback` triggers promotions.** After
  all retries complete, the wrapper dedupes the winning addresses
  across the batch, loads contacts once, and calls
  `promote_contact_address` for each. Wrapped in `pcall` so a
  malformed contacts file can't take down the sync cycle.
- With Phase 3 in place, the "every sync cycle keeps trying the dead
  first IP" behavior self-corrects on the first fallback — the dead
  address drops to the back of the list, the live one moves to the
  front, and subsequent cycles hit it first.

Deferred to a separate issue (per-IP ports):

- **Problem.** `contact.port` is a single scalar shared across every
  address in `contact.ips`. A contact whose LAN interface listens on
  port 22 and whose WAN port-forward lands on 8025 can't be
  expressed today.
- **Proposed syntax.** Embed the port in the `ip` value:
  - `alice.ip = 192.168.1.5:22`          (IPv4 + port)
  - `alice.ip = alice.duckdns.org:8025`  (hostname + port)
  - `alice.ip = [2001:db8::1]:8025`      (IPv6 + port, brackets
     required to distinguish from bare IPv6)
  - `alice.ip = 192.168.1.5`             (inherits `alice.port`)
- **Parser.** A small `parse_endpoint(value, default_port)`:
  1. Match `[IPv6]:port` → (addr, port).
  2. Match `[IPv6]` → (addr, default_port).
  3. Otherwise: if the value contains `:` but looks like a bare
     IPv6 (multiple `:` or `::`), treat the whole thing as the
     address with default_port. Else split on the last `:` and use
     the numeric tail as the port.
  4. If none of the above matches, treat as host-only with
     default_port.
- **Shape of the data structure.** `contact.endpoints` becomes a
  list of `{addr, port}` pairs. `contact.ips` stays (addresses only)
  for callers that still need just the address list. `contact_hosts()`
  today returns a string list; an `contact_endpoints()` variant
  would return the pairs for callers that need the port too.
- **Migration.** A contacts file with no `HOST:PORT` syntax and a
  `name.port = ...` line keeps working identically. Users opt in
  per-line.
- **Scope note.** Not implementing now — the daemon currently works
  for single-port setups, which covers the common case. Spawn a new
  issue when someone wants this.
