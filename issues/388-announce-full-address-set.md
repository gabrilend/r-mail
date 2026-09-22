# #388 — Announce the full address set, and confirm it before clearing the notice

## Problem

An address announcement sends **one** address and overwrites **one** field.
That is lossy in a way that actively breaks working setups.

A contact on our own LAN may hold our LAN address for us, which is the
correct and fastest route between us. When we announce, we send our
*public* address, `handle_update_address` overwrites their `.ip`, and from
then on they reach us only by hairpin NAT — measured on this router at
roughly 70% success with handshakes up to 10s (see #377 notes). A working
route is replaced by a worse one, silently, by the peer who knows least
about which route works.

The unconditional startup announce added alongside #377 makes this fire on
every restart rather than only on a real IP change.

## Why the sender cannot just pick better

The sender knows its *own* addresses. It cannot know which of them is
reachable from any particular contact — that depends on the contact's
network position, which only the contact can discover. Picking one address
to send is the wrong shape for the problem.

## Intended behavior

### Announce the set, not an address

The payload carries every address we have: public IPv4, LAN IPv4, global
IPv6, and a configured hostname if there is one. `ip`/`port` stay in the
payload unchanged so older peers keep working.

The receiver stores all of them. #347's machinery already does the rest:
`contact_endpoints` tries them in order, `http_post_batch_with_fallback`
falls back on failure, and `promote_contact_index` moves whichever one
worked to the front. A same-LAN contact converges on the LAN address; a
remote contact converges on the public one. Neither needs to be told.

This turns the announcement from destructive into the best available
source of address truth, because we are the only party that knows all of
our addresses.

### Merge rules

Classify with `is_private_ipv4` (fixed in f0f4814 — the old test claimed
all of 172/8 and missed CGNAT).

- **Public addresses**: ours to overwrite. Replace the ones we previously
  announced.
- **Private addresses**: never overwrite. We cannot know whether their
  route to our LAN address works, and they can.
- **Hostnames**: preserved, as today. Re-resolution already handles IP
  churn, which is the whole reason to use one.
- If their pinned default (`name.ip`, unindexed, immune to promotion) is
  private or a hostname, leave it as the default and write our public
  addresses as indexed `ip[N]` entries so promotion can still reorder them.

### Confirm before clearing the notice

Delivering the announcement proves *we* can reach *them*. It says nothing
about whether they can reach *us* — our inbound path may still be broken
by a stale port-forward or a firewall rule, and we would have "confirmed"
nothing.

The confirmation is the return trip: the notice clears on the first
authenticated **inbound** request from that contact. Announce is the SYN,
their next connection to us is the ACK. Until it arrives the notice
stands, which is correct — an unconfirmed address change is exactly the
thing that should still be sitting in an inbox.

### Machine-generated notices are hidden files

Daemon-written notices get a `.` prefix: `.address-update-<name>`. There is
already an informal class of these (`address-update-*`,
`*-consent-to-download-form`, `rmail-delete-for-me-only-*`, `declined-*`)
and formalising it lets the message list ignore them by rule.

**Trap:** hiding must not mean losing. `list_files(INBOX)` and the Android
file listing must deliberately still *sync* dotfiles while excluding them
from the message list, or notices silently stop replicating to the phone.

## Phase 2 — `pending-address.json` becomes real files

The pending queue is a queue of outbound machine-generated messages kept
in an opaque state file. As mailbox files it would be hook-visible (an
`on_send` hook could rewrite or suppress an announcement), inspectable,
and hand-deletable when a contact is gone for good.

Deliberately *not* extended to the other state files:

- `consent-pending.json` / `consent-responses.json` — the consent form is
  already a mailbox file, and its job as a live per-chunk progress bar is a
  feature that moving would break. Auto-delete on completion; change
  nothing else.
- `chunks-outgoing.json`, `uploads.json` — already self-cleaning; entries
  are removed as transfers complete. Verified empty in normal operation.
- `inbox.json` / `outbox.json` — per-recipient delivery bookkeeping, not
  documents. Highest risk, least benefit. Leave last if ever.

## Status

**Phase 1 implemented 2026-09-22.** Phase 2 (`pending-address.json` as
mailbox files) not started.

Verified end to end against a loopback peer pair: a contact holding
`127.0.0.1` for us keeps it as the pinned default and gains the public and
LAN addresses as `ip[1]`/`ip[2]`. Before this change that private address
was overwritten outright.

### Three bugs found while building it, all worth recording

**The handshake was implemented backwards.** The notice says "their address
changed"; what retires it is *us reaching them at the new address*, not
them reaching us. Receiving from them proves only that they can reach us,
which was never in doubt -- they sent the announcement.

**A notice could never retire on an idle pair.** Confirmation needs
outbound traffic and an idle pair generates none, so the notice sat
forever. Fixed by having the notice queue an announcement of our own: the
claim generates the traffic that tests it. Deliberately reuses the existing
announcement rather than `/peer-address`, which #365 removes.

**An unchanged set still rewrote the contacts file**, which fired the
contacts inotify watcher, forced an immediate sync, re-announced to the
peer, and came straight back. Two idle daemons produced ~1,500 exchanges
and 350KB of log in fifteen seconds. Three separate causes, each hiding the
next:

1. The write was not gated on the set having changed at all.
2. The comparison read `_indexed_ips`, which `load_contacts` **nils out**
   once it has built `endpoints` -- so "before" was always just the default
   address and never matched "after". Read `endpoints` instead.
3. The comparison was order-sensitive over a `pairs` traversal, whose order
   is undefined. Compare sorted sets: which address sits first is a local
   decision that promotion owns, so a reordering is not news.

The general lesson: any write to a watched file needs a "did this actually
change anything" guard, or the watcher turns it into a feedback loop.

### Known gap

`list_files` skips dotfiles, so `.address-update-*` notices do **not**
currently sync to the Android client -- the trap flagged above is real and
unfixed. `list_notices` exists for daemon-side management of them, but the
sync manifest and the client's listing still need to carry dotfiles while
excluding them from the message list.
