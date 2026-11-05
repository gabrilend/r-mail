# #409 — Announce the full address set, and confirm it before clearing the notice

## Current Behavior

Phase 1 built 2026-09-22 (see Status): announcements carry the whole
address set (`ips`: hostname, public IPv4, IPv6; `local_ips` only to a
contact on our LAN); the receiver merges it under the contact's pinned
`ip`, files private addresses on its own /24 as `local-ip`, and writes the
file only when the set really changed.  A real change leaves a hidden
`.address-update-<name>` note that queues our own announcement as a test,
removed by the first request that reaches them.  Phase 2 built
2026-11-05: an owed announcement is the hidden file
`outbox/.address-announcement-<name>`, not an entry in
`.state/pending-address.json`; `on_send` sees it, and deleting it by hand
means it is not sent.


## Problem

An address announcement sends **one** address and overwrites **one** field.
That is lossy in a way that actively breaks working setups.

A contact on our own LAN may hold our LAN address for us, which is the
correct and fastest route between us. When we announce, we send our
*public* address, `handle_update_address` overwrites their `.ip`, and from
then on they reach us only by hairpin NAT — measured on this router at
roughly 70% success with handshakes up to 10s (see #115 notes). A working
route is replaced by a worse one, silently, by the peer who knows least
about which route works.

The unconditional startup announce added alongside #115 makes this fire on
every restart rather than only on a real IP change.

## Why the sender cannot just pick better

The sender knows its *own* addresses. It cannot know which of them is
reachable from any particular contact — that depends on the contact's
network position, which only the contact can discover. Picking one address
to send is the wrong shape for the problem.

## Intended Behavior

### Announce the set, not an address

The payload carries every address we have: public IPv4, LAN IPv4, global
IPv6, and a configured hostname if there is one. `ip`/`port` stay in the
payload unchanged so older peers keep working.

The receiver stores all of them. #408's machinery already does the rest:
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

## Suggested Implementation Steps

1. Built: `addrset.mine`, `addrset.merge`, `addrset.write`,
   `addrset.write_local`, `addrset.same_lan`, `addrset.contact_on_lan`;
   `handle_update_address`; `sync_address_notifications`; the note's
   removal in `run_sync_cycle`.  (The test once named here,
   `scripts/test-lan-address-learning.sh`, tested addresses learned from
   incoming connections, not announcements; it was deleted with that
   learning by #418.  The announcement merge is tested by
   `scripts/test-address-announcements.sh`, since phase 2.)
2. Built 2026-11-05: an owed announcement becomes a hidden file in the
   outbox (one per contact), visible to `on_send`, deletable by hand; the
   state file goes.  Test: `scripts/test-address-announcements.sh`, which
   includes an announcement deleted by hand not being sent.

## Status

**Phase 1 implemented 2026-09-22.  Phase 2 implemented 2026-11-05** (see
"Phase 2 built" below).

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
announcement rather than `/peer-address`, which #418 removes.

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

### Follow-up (2026-09-22): private addresses split into `local-ip`

Phase 1 sent every address to every contact.  A remote contact can never
use our 192.168.x.x -- and on *their* network the same address names some
other device, so trying it knocks on a stranger's machine.  Changed:

- **Contacts file**: new `name.local-ip` / `name.local-ip[N]`, private IPv4
  only (a public value is ignored with a warning; private IPv6 is ignored
  with a "not supported yet" warning, since the subnet check below is
  IPv4-only).  Legacy `name.lan_ip` folds in.
- **Connecting**: `contact_endpoints` puts local addresses first, but only
  those sharing our /24.  They carry no index, so a win on one never
  promotes or rewrites `ip`.
- **Announcing**: `addrset.mine` returns `(public, local)`, classifying by
  the address rather than the state file it came from (a CGNAT "public IP"
  is not public).  `ips` carries public only; `local_ips` is sent only to a
  contact we hold a same-/24 private address for (`addrset.contact_on_lan`).
- **Receiving**: private entries -- from `local_ips`, or from a phase-1
  peer's `ips` -- are kept only if they share our /24, and replace the
  sender's `local-ip` lines wholesale.  One that phase 1 wrote into an
  indexed `ip[N]` is moved out.  Absent `local_ips` leaves them alone.
- **Canonical contacts form** now carries `ip[N]`, `port[N]` and
  `local-ip`.  It did not carry `ip[N]` before either: the phone holds this
  text, and a contact edit on the phone posts it back as the whole file, so
  any indexed address was deleted on the server.  Pre-existing since #408.
- **Android**: settings take a list of server addresses and a list of
  local addresses (`+` to add, `−` to remove, no reordering).  A private
  address in the public list is refused on save; configs from before the
  lists have a private host sorted into the local list automatically.
  `HostPicker` probes same-/24 local addresses (1s) then public ones (3s)
  at the start of each sync cycle; other calls reuse that answer until
  the next sync.

Classification is `is_private_ipv4`: 10/8, 127/8, 172.16/12, 192.168/16,
169.254/16, 100.64/10 (CGNAT).  Note CGNAT is also Tailscale's range, so a
Tailscale address counts as local and will only be tried from a matching
/24 -- use `ip[N]` for one.

### No notification; the dotfile is a confirmation marker (2026-09-22)

Address changes were already applied automatically on receipt, and
announcing was already unconditional -- `notify_ip_change` only decided
whether the *receiver* wrote a human-readable notice (the config comments
and install/migrate scripts described it as gating the announcement, which
it never did).  The setting is removed.  `.address-update-<name>` is now
written on every real change regardless of the sender's `notify` flag, and
is purely bookkeeping: it drives the confirm-by-outbound-send handshake
above and is deleted automatically on the first successful send.  The
`notify` field is no longer sent: every peer is upgraded together, so
there are no pre-#409 receivers to keep quiet.

This dissolves the known gap below: a marker the user never acts on has no
business on the phone, so `list_files` skipping dotfiles is correct.

### Portable mailboxes announce only when asked

A portable mailbox has no service and never starts on its own; the drive
now carries two launchers inside the mailbox instead of a root `run.sh`,
and running one is the decision to be reachable on this host:

- `sync-with-contacts.sh [SECONDS]` runs the daemon with `--once`: the
  startup announcement goes out (which resets each contact's backoff timer
  for us, so they deliver immediately), a sync runs, the daemon stays
  reachable SECONDS (default 60) and exits.  This is the same primitive
  #419's wake-to-sync needs.
- `auto-sync.sh` runs the normal cycle until the drive is pulled.

Both run the program from a temporary copy on the host, and the daemon now
exits cleanly when its mailbox directory disappears (checked every 3s, two
misses in a row), so a pulled drive stops the daemon instead of crashing
the interpreter mid-page-fault.

### No guessing from digits (2026-09-23)

Public vs local is never inferred from an address's digits any more:
private ranges are reused everywhere, carrier NAT hands out private-looking
public addresses, and a second router puts a reachable "private" network
where the /24 rule says there is none.  Instead:

- **Own addresses** are split by *source*: `.state/public_ip` (what outside
  services see) is public, `.state/lan_ip` (our interface) is local.
- **Received announcements** are filed by the sender's labels: `ips` ->
  `ip`, `local_ips` -> `local-ip`.  No /24 filter on storing.
- **`local-ip`** in the contacts file is kept as written (a warning only for
  non-IPv4, which the same-network check cannot use yet).
- **"On our LAN"** (whether to send our local address) = we hold a
  `local-ip` for that contact, i.e. we were told.
- **`ours_to_replace`**: every non-hostname `ip` entry.  Hostnames are told
  apart by syntax, which is certain.
- **Android**: the Add-address dialog has a Public/Local switch; Setup has
  the same switch; no validation against digits; saved configs are no
  longer re-sorted on load.

Still inferred, deliberately: *whether this device is on that network right
now* (same-/24 before trying a local address, daemon and phone).  Open
question whether to relax it for multi-router homes.  Also still present:
the pre-#365 LAN-peer cache, which goes with #365.

### Known gap (resolved -- see above)

`list_files` skips dotfiles, so `.address-update-*` notices do **not**
currently sync to the Android client -- the trap flagged above is real and
unfixed. `list_notices` exists for daemon-side management of them, but the
sync manifest and the client's listing still need to carry dotfiles while
excluding them from the message list.

### Phase 2 built (2026-11-05)

`.state/pending-address.json` is gone.  An announcement owed to a contact
is the file `outbox/.address-announcement-<name>`:

```
// rmail owes alice an announcement of this mailbox's addresses (#409).
// It goes at the next sync and this file is then removed.  Delete it
// and it is not sent.  The addresses sent are read when it goes.
ip = 198.51.100.7
port = 8025
```

All four writers write it: a confirmed public-IP change, an IPv6 change
(merged into one already owed), the start-up announcement, and an
unconfirmed `.address-update-<name>` notice.  `sync_address_notifications`
reads the files, sends each through `on_send`, and removes a file once its
announcement has reached the contact.  A file for a contact removed, or
marked listen-only, is removed and logged.  The functions live in the
`addrset` table (`owed_path`, `read_owed_file`, `owe`, `owed`, `paid`), not
as new top-level locals, since the main chunk is at Lua's limit of 200.

Tested by `scripts/test-address-announcements.sh`: two mailboxes on this
machine, run in a network namespace with only loopback, with the sender's
public address written into its `.state` by hand, so nothing is looked up
outside.  It covers:
- a legacy `pending-address.json` moved into a file and removed;
- the start-up announcement waiting as a file while the receiver is down;
- the file deleted by hand, and the announcement not sent;
- `on_send` rewriting an announcement;
- a footer-printing hook refused;
- the merge: a hostname kept as the pinned default, the public address
  as `ip[1]`, the local address as `local-ip`;
- a repeat announcement that changes nothing leaving the receiver's
  contacts file unwritten.

All 16 cases pass.  Against the base `rmail.lua`, 11 fail.

### Decisions (2026-11-05)

Made by the builder.  The owner's standing instruction is to answer open
questions rather than wait, choosing the option that is easiest to undo.
Each can be overturned.

1. **Where the file goes: the top of the outbox,** as
   `.address-announcement-<name>`.  It mirrors
   `inbox/.address-update-<name>`.  The alternative was
   `outbox/<name>/.address-announcement`, which would have made the daemon
   create contact folders.  Under #214 a contact folder sends every file put
   in it, so a folder the user did not make would change what their outbox
   does.  Undo: change `addrset.owed_path`.
2. **The file says what was owed; what is sent is computed when it goes.**
   The file holds `ip`, `port` and `ipv6`, as the state entry did.  The set
   sent is read from `addrset.mine` at send time, as in phase 1, so an
   announcement that waited through another change carries the current
   addresses.  A hand edit of the file's `ip` changes only the
   `ip`/`port` fields that pre-#409 peers read.
3. **`on_send` sees an announcement as it sees a message.** It gets the
   contact as `$1`, the file's name as `$2`, and the JSON on stdin and in
   `$3`.  Its output replaces the announcement only when the whole output
   is one JSON object.  A hook written for message bodies, such as a footer,
   would otherwise break every announcement.  That case is logged, and the
   announcement goes as computed.  A failing hook is logged, and the
   announcement goes as computed: this is #215's rule for `on_send`.
   Holding announcements alone on a failing hook would answer #215's open
   question 1 for one kind of message only.  Undo: one branch in
   `sync_address_notifications`.
4. **To stop an announcement, delete its file.** This is the only way, and
   the hook is not one.  Two writers can owe it again, as before:
   - the start-up announcement, at each start;
   - an `.address-update-<name>` notice still standing in the inbox. Delete
     the notice too to stop that one.
5. **A legacy `pending-address.json` is moved, not ignored.** The first
   time anything reads or owes, each entry becomes a file, unless that
   contact already has one.  The state file is then removed and the move
   is logged.
6. **Not on the phone.** The file is a dotfile, so `list_files` skips it
   for the outbox sync and the phone listing.  This matches the decision
   already made for `inbox/.address-update-*`: bookkeeping the user never
   acts on has no place in a message list.
7. **Written only when its text changes.** The outbox is watched, and an
   unchanged rewrite would start a sync for nothing.  This is the lesson
   from phase 1's feedback loop.
8. **The other state files stay as they are,** as the issue says.
9. **Base: #206's branch** (`claude/206-duplicate-filename-warning`), the
   tip of the #216, #215, #214, #211, #206 chain.  The change calls
   `run_hook` with #215's body-as-table signature and #215's `on_send`
   rule.  It puts its file in the outbox that #214 restructured and that
   #211 and #206 now check.  The other open line, #120, #121 and #118,
   wraps the call in `ctimer.hold({"pending-address.json"}, ...)` and a
   pass descriptor naming that file.  Whichever of the two lines merges
   second must drop that name: no state file is touched any more, so the
   hold has nothing to lease.
10. **A finding about the merge rule.** "No guessing from digits"
    (2026-09-23) made every non-hostname `ip` ours to replace.  So a
    private address held as a pinned default is now replaced by the
    announced public address.  The Status paragraph above, about
    `127.0.0.1` being kept as the default, describes the rule before that
    day.  So does the Merge rules section's "Private addresses: never
    overwrite".  A private address meant to stay belongs in `local-ip`
    now.  The test uses a hostname as the pinned default (it is kept),
    which is the rule as it stands.
