# Synced phone config (rejected)

## Why this file exists

The original proposal was to give the Android client its own
server-synced config file — separate from the desktop config,
editable on both phone and desktop, kept in sync via the same
hash-compare mechanism as contacts.  The issue shipped in the design
phase with an explicit "is this actually needed?" section.  Nothing
has surfaced to justify the build, so this is a rejection record
instead of an implementation plan.  Kept so the same idea doesn't get
re-proposed without this context.

## Candidates considered (and why each falls apart)

- **IP updates.**  The daemon already owns its own public IP and
  manages its own contact-side updates via `/update-address`.  The
  phone never needs to write it.

- **Phone-specific display settings** (theme, font, notification rules,
  per-mailbox overrides).  These are genuinely phone-local.  There is
  no desktop surface that edits them, so there is nothing on the desktop
  to sync *from*.  Backup-and-restore if the user re-installs is a
  different problem — solvable with Android's own per-app backup
  hooks, not by routing state through the daemon.

- **Hook-script bindings.**  Explicitly ruled out by #309's phone/
  desktop separation principle: phone and desktop hooks are
  independent.  No round-trip.

- **Daemon-side settings the phone needs to know** (sync interval,
  chunk size, max attachment size).  These are daemon-internal; the
  phone doesn't need to mirror them.  Anything the phone needs at
  runtime it can ask for, or know by protocol contract.  Examples in
  the codebase today: the phone learns the daemon's public IP on demand
  (`/api/myaddress`) rather than caching it.

- **Multi-phone preference sync.**  If a user had a phone and a tablet
  they might want both to show the same settings.  Configuration each
  once is cheap, and the failure mode (a divergent per-device
  preference) is not a real problem — nobody's blocked by two devices
  showing the inbox in different orderings.

- **Contact display names / aliases.**  Would be a reasonable sync
  target, but aliases are UI state the phone can maintain privately.
  No need to push them through the daemon.

## Implementation cost if we did it

- New API endpoints on the daemon: `GET /api/phone-config`,
  `POST /api/phone-config`, hash compare.
- New file type in `~/mail/` (e.g. `phone-config`) with its own
  conflict-resolution rules (the issue proposed "phone wins", inverse
  of contacts — which itself would be novel asymmetry and needs
  justification).
- Android-side read/write with proper state management, merge handling,
  and invalidation.
- Documentation for a second sync target plus its semantics.

The cost is real.  There's no use case to pay for it.

## Downstream effects of rejection

- **#309 (Android script editor)**: removed `#308` from its
  dependency list (if present).  Phone script editor does not need
  synced config.
- **#310 (Periodics)**: already decoupled — the desktop variant is
  independent of any phone config work, and the phone variant is
  low-priority on its own.

## If this should be revisited

Reopen if, and only if, a concrete use case lands — one that can
specify: (a) what field is shared, (b) who authors changes, (c) why
that field can't live on one side alone, (d) why the cost of a new
sync channel is less than the cost of solving the problem some other
way.

## Status

Rejected.  Keep this file in `issues/` (not `issues/completed/`) so
the design-history is visible in the main issue listing.
