# #319 — Investigate or remove orphan + button on Android

## Problem

A + button in the Android app appears to do nothing when tapped. The
exact screen where this was noticed is not recorded, and the app has
several + buttons across different screens.

## Action

1. Enumerate every `+` button in the Android app: which screen, which
   top-bar/bottom-bar slot, and what it does (or is supposed to do).
2. Identify which one is the dead button.
3. Either wire it up to the intended function (suspected: add
   attachments) or remove it.

## Source

From `rmail-android-plus-button-in-compose-screen`.

## Status

Shipped.

### Audit

Every `+` button in the Android app, by screen and role:

| Screen / panel       | + action              | Status |
|----------------------|-----------------------|--------|
| Inbox panel          | *(no `+` — refresh)*  | —      |
| Outbox panel         | Write new message     | Keep   |
| Contacts panel       | Add contact           | Keep   |
| Files panel          | Upload file           | Keep   |
| Write panel          | **Clear draft form**  | **Removed (#319)** |
| Contact editor       | Add custom field      | Keep   |
| Message composer     | Add recipient         | Keep   |
| Message composer     | Attach file           | Keep   |
| Mailbox list         | Add mailbox           | Keep   |

### Fix

Removed the Write-panel `+` button. With an empty draft it looked
like it did nothing (the likely source of the original bug
report); with a filled draft it silently wiped the user's work.
Users who want a fresh draft can edit fields directly or navigate
away and back. Only the Send action stays in the Write-panel
top bar.
