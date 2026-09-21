# #373 — Android: swipe-to-delete should default to OFF

## Summary

Make the inbox "swipe to delete" gesture **disabled by default**.  The
setting itself already exists — this is a default flip, not a new
feature.

## Current state (already implemented)

A per-mailbox `swipeToDelete` toggle already ships in the current
source, defaulting to **`true`** (enabled):

- `data/MailboxRegistry.kt:15` — `val swipeToDelete: Boolean = true`
- `data/MailboxRegistry.kt:89` — `prefs.getBoolean("swipe_to_delete", true)`
- `data/MailboxRegistry.kt:116` — `obj.optBoolean("swipe_to_delete", true)`
- Toggle UI: `ui/screens/SettingsScreen.kt:110` and
  `ui/screens/InboxScreen.kt:1296` (a `Switch`)
- Wired into the list: `InboxScreen.kt:619`
  `MessageList(inboxFiles, "No messages", vm.swipeToDelete, …)`

So a user on an up-to-date build can already turn it off.  (The
reporter's installed client predates the setting — an APK rebuild is
needed regardless of this change.)

## Change requested

Flip the default from enabled to **disabled**.  Swipe-to-delete is a
destructive, easy-to-trigger gesture; opt-in is the safer default,
especially since deletes propagate to the server on sync.

Concretely, change the three default literals from `true` → `false`:

- `MailboxRegistry.kt:15` — data-class default
- `MailboxRegistry.kt:89` — `getBoolean("swipe_to_delete", false)`
- `MailboxRegistry.kt:116` — `optBoolean("swipe_to_delete", false)`

And the UI fallbacks that read `?: true`, for consistency when
`activeConfig` is null:

- `SettingsScreen.kt:32`, `InboxScreen.kt:1229`, `InboxScreen.kt:1265`
  — `activeConfig?.swipeToDelete ?: false`

## Consideration

Existing installs that already persisted `swipe_to_delete = true` keep
their value (the default only applies to new/unset mailboxes) — so this
is a safe change for current users; only fresh setups get the new
default.  If we want to *also* flip existing users to off, that needs a
one-time migration, which is probably overkill — note but don't do it
unless asked.

## Resolution — feature removed entirely (superseded)

Rather than flipping the default, swipe-to-delete was **removed from
the app altogether** (2026-08-25).  The reporter kept deleting messages
by accident, and a gesture that destructive isn't worth keeping behind
a toggle nobody discovers until after the first accident.

Removed:

- `data/MailboxRegistry.kt` — `swipeToDelete` field, its `getBoolean` /
  `optBoolean` reads, and its `put` in `toJson`.  The legacy-migration
  `prefs.edit().remove("swipe_to_delete")` cleanup stays, so the stale
  pref key is still swept off old installs.
- `ui/MainViewModel.kt` — the `swipeToDelete` accessor.
- `ui/screens/InboxScreen.kt` — the `SwipeToDismissMessageItem`
  composable, the `swipeToDelete`/`onDelete` params on `MessageList`,
  the settings-panel `Switch`, and the now-unused `animateColorAsState`
  import.
- `ui/screens/SettingsScreen.kt` — the `Switch` and its state.

Note the outbox list had swipe-to-delete hardcoded **on** (`MessageList(
outboxFiles, "Outbox is empty", true, …)`) with no toggle at all — that
path is gone too.

Deleting still works: `ReadScreen.kt:65` has an explicit delete button
that calls `deleteOutboxFile` / `deleteInboxMessage`, so the only change
is that a delete now takes opening the message first.

Existing `mailboxes.json` files keep their now-ignored `swipe_to_delete`
key; `parseConfig` just doesn't read it, and the key drops out on the
next save.  No migration needed.

## Status

Closed — resolved by removal, not by the default flip described above.
