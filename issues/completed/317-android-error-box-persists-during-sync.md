# #317 — Keep "failed to connect" error visible during sync

## Problem

The "failed to connect" error box disappears while syncing. The user loses
context about what went wrong.

## Fix

The error box should remain visible during the sync attempt and only be
cleared when the sync succeeds.

## Source

From `r-mail-android-error-box-refresh`.

## Status

Closed — verified by code inspection, behavior already matches the
requested spec.

`MainViewModel._syncError` is only cleared in two places:

1. `selectMailbox()` — explicit mailbox switch.
2. `triggerSync()` on the **success** branch.

Starting a sync sets `_syncStatus = SYNCING` but leaves
`_syncError` untouched. `InboxScreen`'s error surface renders on
`syncError != null` with no `syncStatus` condition, so the red
box stays visible throughout a sync-in-progress and only vanishes
when the sync actually succeeds. A subsequent failed sync replaces
the message with the new error text rather than blanking it.

No code change required.
