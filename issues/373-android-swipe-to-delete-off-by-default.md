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

## Status

Open.
