# #317 — Keep "failed to connect" error visible during sync

## Problem

The "failed to connect" error box disappears while syncing. The user loses
context about what went wrong.

## Fix

The error box should remain visible during the sync attempt and only be
cleared when the sync succeeds.

## Source

From `r-mail-android-error-box-refresh`.
