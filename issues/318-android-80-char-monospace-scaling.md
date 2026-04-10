# #318 — Scale inbox message view to 80-character monospace width

## Problem

Message text in the inbox viewer doesn't adapt to screen size. Messages
written assuming 80-character terminals look wrong on phones.

## Requirements

- When viewing an inbox message, use a monospace font scaled so that
  exactly 80 characters fit the screen width.
- Add a +/- control (top of screen) to adjust in increments of 20
  characters of extra width (so: 80, 100, 120, or 60, 40).
- Persist the user's width preference across sessions.

## Source

From `rmail-80-character-android-view`.
