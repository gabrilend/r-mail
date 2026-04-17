# Shared files via on_update hook (experiment, rejected)

## Why this file exists

`helpers/shared.lua` briefly existed in the repo as an `on_update` hook
that made living messages bi-directional — both users could edit a shared
file and see each other's changes. It was removed after design review
surfaced problems that couldn't be solved without daemon changes. This
file documents what was tried, what broke, and why we didn't ship it, so
the same design doesn't get re-attempted without this context.

## Goal

Bi-directional shared files between two users. Alice edits
`outbox/meeting-notes`, Bob sees the change. Bob edits, Alice sees it.
Like a minimal collaborative document, reusing the existing living-message
mechanism.

## How it worked

The `on_update` hook fired on the receiving side when a living message
arrived. The hook wrote the new body into the recipient's matching outbox
file (preserving its existing `to:` / `attach:` headers), which caused
the daemon's outbox inotify watcher to fire, triggering a sync back the
other way. Loop prevention relied on the daemon's body-checksum check:
when the mirrored content arrived at the original sender, the body matched
what was already in their outbox, so no further update was sent.

Auto-creation on first update: if the recipient's outbox had no matching
file, the hook created one with `to: <sender>\n<body>`, bootstrapping the
mirror without manual setup.

## Design iterations considered and discarded

1. **Companion inotify watcher script** to catch local inbox edits. Worked
   technically (reused `rmail_inotify.so` with the same `getfd()` +
   `socket.select()` pattern as the daemon), but required running a second
   process alongside the daemon. Dropped in favour of just documenting
   "edit the outbox file, not the inbox one."

2. **Piggyback on the daemon's inotify fd** to avoid a second process.
   Blocked by `IN_CLOEXEC` on the fd (hook subprocesses can't inherit it)
   and by the fact that the daemon's event loop treats all inotify events
   as "outbox changed" — it wouldn't know what to do with an inbox-file
   event.

3. **Hide the inbox copy with a dot prefix** so users only see one file
   (the outbox) to edit. Blocked by the daemon controlling the inbox
   filename and writing `inbox.json` *after* firing `on_receive` — a hook
   rename would race with the daemon's `save_state`, and `sync_inbox`
   would later see the expected filename missing and treat it as a user
   deletion.

## Problems that killed it

Four separate issues, none fixable from a hook alone:

1. **Deletion leaves zombies.** When Alice deletes her outbox file, the
   daemon tells Bob to delete his inbox copy. Bob's outbox mirror (a
   separate message with its own `message_id`) isn't touched. Bob's
   daemon keeps trying to sync that file back to Alice, effectively
   re-creating it. To fix properly, `on_delete` would need to receive
   the filename and/or `message_id` — currently it only gets the sender
   name.

2. **Filename collisions break the mirror.** If Bob already has an
   unrelated `inbox/meeting-notes` from Charlie, the daemon saves
   Alice's message as `meeting-notes-from-alice` (see `rmail.lua:833`).
   But Bob's outbox file for Alice is still named `meeting-notes`.
   The hook matches by filename, so it mirrors into the wrong file or
   creates a new mismatched one. Regular living messages sidestep this
   by routing updates via `message_id`; the hook can't, because
   `on_update` doesn't pass the message id.

3. **Auto-creation is indiscriminate.** The hook can't distinguish "this
   is a shared file" from "this is a regular living message that got
   updated." Any `on_update` would create an outbox mirror, even for
   messages the recipient never intended to share. There's no opt-in
   mechanism short of adding a header line convention that the daemon
   would need to respect.

4. **Hub model trust issues.** If Alice has `to: bob` and `to: gary`,
   Bob's edits flow through Alice's outbox to Gary. There's no way for
   Gary to receive Alice's edits but not Bob's. This is a property of
   the "Alice is the hub" design, not a bug — but it's an unexpected
   information flow that's easy to miss.

## What it would take to do this properly

Not a hook. A first-class daemon feature:

- `shared: true` header line in the outbox file to opt in
- Paired `message_id` tracking in state (inbox id ↔ outbox id for each
  shared file)
- Delete propagation that handles both sides atomically
- `message_id` routing instead of filename matching (already how regular
  living messages work — shared files would just extend this)

That's substantial work. Not scheduled. See also:

- `issues/306-living-messages-on-update-hook.md` — the living-message
  mechanism this was trying to extend
- `issues/323-delete-edit-race-condition-matrix.md` — related race
  discussions

## Files removed

- `helpers/shared.lua`
- `docs/helper-scripts.md` — "shared.lua — bi-directional shared files" section
- `docs/scripting-tutorial.md` — "Bi-directional shared files" example section
  and the `helpers/shared.lua` reference in the `on_update` hook description

## Hook interface changes that came out of this

None directly. The `on_update` hook (added in issue 306) stays as-is. The
scripting tutorial was reorganized during the cleanup (TOC added, examples
reordered easiest-to-hardest, redundant tips merged into hook descriptions,
Lua shebang updated to point at rmail's bundled interpreter) but those
changes stand on their own regardless of this experiment.

## Status

Rejected. Keep this file as a design-history record so the same approach
isn't rebuilt without this context.
