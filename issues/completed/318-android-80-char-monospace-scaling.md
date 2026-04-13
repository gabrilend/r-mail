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

## Status

Shipped.

- New `Settings.readerColumns` SharedPreferences entry, default 80,
  range 40–200.
- ReadScreen wraps the message body in a `BoxWithConstraints` and
  uses `rememberTextMeasurer()` to measure a row of `columns` "M"
  characters at a 14 sp reference; the rendered font size is then
  scaled so that row exactly matches the available width. Result:
  exactly N monospace characters fill the screen width regardless
  of device density.
- Top bar gains `–` and `+` IconButtons on the inbox-view path
  (hidden for outbox / consent so they don't clutter unrelated
  screens). Each tap adjusts `readerColumns` by ±20 and persists.
- `MainViewModel.bumpReaderColumns()` exposes the value as a
  `StateFlow<Int>` so the ReadScreen recomposes when the user taps
  the controls (SharedPreferences alone wouldn't trigger
  recomposition).
