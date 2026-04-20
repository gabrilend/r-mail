# #369 — Android UI for contact-named outbox folders (blocked on #368)

## Problem

#368 adds a daemon-side feature: files in `~/mail/outbox/<contact>/`
get sent to that contact automatically, with nested directory
structure mirrored on the receiver's side. Once that lands, the
Android app needs to understand the same layout so users can
create, view, edit, and delete contact-folder messages from their
phone the same way they handle regular outbox messages today.

Without Android support, a user who adopts the contact-folder
workflow on the daemon side sees *nothing* for those messages in
the phone's outbox view — a confusing blind spot.

## Depends on

**#368** must land first. This issue is purely about surfacing the
daemon's directory semantics in the Compose UI; it assumes the
on-disk layout, state keys, and wire protocol are already in place.

## Proposal

The Android outbox needs to:

1. Display contact-folder files under their contact, not flattened
   into a single list.
2. Let the user create a new file inside a contact folder — ideally
   with one tap from the contact view or from a contact folder view.
3. Handle nested directories from #368 (display them as an
   expandable tree, or flatten with visible path prefixes — see
   "Open design questions" below).
4. Keep the regular flat-outbox view working unchanged for users
   who prefer that workflow.

## Design details

### Outbox list: grouped by contact

The current `OutboxScreen` (see the Compose code under
`clients/android/app/src/main/java/com/rmail/app/ui/screens/`)
shows a flat list of outbox files. Post-#368, the list contains
two kinds of entries:

- **Top-level files** — one `to: <name>` line or more, displayed
  as a single row with the subject and recipient(s).
- **Contact-folder files** — addressed by location. Grouped under
  a contact header, so the UI reads

  ```
  [top-level row]  project-kickoff   → alice, bob
  [top-level row]  quick-thought     → carol

  ▾ alice
      quick-note
      birthday-plan
      projects/q2-plan     ← nested: path prefix visible
  ▾ bob
      weekly-check-in
  ```

Contact-folder groups are expandable/collapsible (saved preference
per contact, or just "all collapsed by default, persistent scroll
state" — simpler).

### Creating a new contact-folder message

From a contact's detail view (the screen that shows contact info,
last contact, edit/delete buttons), add a **"Write to …"** FAB or
action button. Tapping it opens the composer pre-populated with:

- Recipient chip: the contact's name, locked (can't be removed —
  the directory placement is what determines routing).
- Additional recipients: the composer's existing multi-`to:` UI
  still works for adding more, same as a normal compose — matches
  #368's "extra `to:` lines are additional recipients, not
  conflicts."
- Subject field: empty, user enters it; becomes the filename.
- Body field: empty.

On save, the client writes the file to
`~/mail/outbox/<contact>/<subject>` via the existing file-put API,
and the daemon picks it up on the next sync.

### Creating from the outbox view

The regular outbox `+` button should offer a picker when multiple
contacts have folders — "top-level" vs each contact folder — so
users can choose where the new file lands. For users who never use
contact folders, the picker short-circuits to the same behavior
as today (top-level only).

### Editing and deleting

Editing a contact-folder file uses the same composer as a top-
level file. Recipient chip for the directory's contact is still
locked (moving a file between contact folders means "delete this
one, create a new one in the other folder" — mirrors the daemon-
side behavior from #368 where that kind of move propagates a
delete + a new deliver).

Deleting a contact-folder file triggers the daemon's delete
propagation path the same as a top-level file.

### Inbox side: display received nested paths

The inbox already groups by sender; #368 introduces nested paths
on the receive side. The inbox list needs to show either:

- The full relative path per message ("projects/q2-plan"), OR
- A tree view collapsible by directory component.

Probably just show the path prefix inline ("projects/q2-plan") on
the row, and let the user tap in to read. Tree views add a lot of
UI complexity for a feature most users might not heavily nest in
practice.

## Open design questions

### Should contact folders be created from the phone?

On the daemon side, the folder is just `mkdir outbox/alice` — no
API call, no daemon interaction. The phone client would need
either:

- A "create contact folder" action from the contacts screen, which
  calls the daemon's file-put API on a dummy file and then deletes
  it (to force `mkdir -p` of the folder path), or
- A first-write-creates-folder approach, where composing "Write to
  alice" on first use implicitly creates the folder as part of the
  write.

Second option is simpler; users never think about the folder
existing, the UI just does the right thing.

### Nested directories: tree or flat with prefixes?

For a handful of nested paths, flat rows with path prefixes
("projects/q2-plan") are the clearest. If a user has dozens of
nested files, a tree view helps but adds complexity. Defer to
flat-with-prefix for v1; if users start nesting heavily we can
revisit.

### Sort order inside a contact folder

Current outbox sorts by mtime (most recent first). Same rule
inside contact folders. Nested paths sort by mtime across the
whole subtree, not lexicographically — matches the "what did I
work on most recently" mental model.

## Non-goals

- **New Compose-specific gestures.** Follow existing rmail Android
  UI patterns — row tap to read, long press to select / delete,
  FAB for new. No reinventing the navigation model.
- **Drag-to-move between contact folders.** Probably a nice
  future addition but too much complexity for v1.
- **Browser-style breadcrumb nav.** The tree depth should stay
  shallow in practice; path prefixes in the row are enough.

## Implementation sketch

- Extend the outbox data model to include
  `{contact: String?, path: String}` per entry — `contact` is
  null for top-level files.
- Group the outbox list in the ViewModel by `contact`, with nested
  paths staying as flat rows inside each group.
- The composer becomes aware of a "target contact folder" when
  invoked from a contact's detail view; it writes to
  `outbox/<contact>/<subject>` instead of `outbox/<subject>`.
- The inbox screen's row renders the full relative path instead of
  just the subject.

All of the above is UI-layer work. Wire protocol and state are
handled on the daemon side by #368.

## Test plan (for q-a-tests.md once this lands)

- Daemon running with a contact folder populated: Android outbox
  view shows the folder as a collapsible group, files inside it
  as rows.
- Tapping a contact-folder row opens the composer with the
  recipient chip locked to the folder's contact.
- Adding an extra recipient chip for bob (to a file in alice's
  folder) saves correctly and the daemon delivers to both.
- Trying to remove the locked recipient chip is rejected (or the
  chip is visually non-removable — pick one).
- Composing from a contact's detail view creates the file in
  that contact's folder; a subsequent sync delivers it.
- Nested path in the inbox renders with its full relative path
  prefix visible on the row.
- Deleting a contact-folder file from the phone triggers the
  daemon's delete propagation (recipient receives the delete on
  next sync).
- Regular (top-level) outbox workflow is completely unchanged for
  users who don't use contact folders.

## Source

User request 2026-04-20 alongside #368.

## Status

Blocked on #368.
