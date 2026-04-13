# #316 — Smart cursor-aware scrolling in Android compose screen

## Problem

When the user types in the compose screen and the cursor goes off-screen
(behind the keyboard or above the viewport), the view doesn't follow
intelligently.

## Desired behavior

- When the cursor goes off-screen, scroll so the cursor line is 3 lines
  above the top of the keyboard.
- As the user continues typing, don't scroll again until they reach the
  last visible line. Then scroll proportionally — 1 pixel per character
  (or proportionally scaled) so that by the time they finish the last line,
  it has become the third-from-bottom line.
- The middle of those three lines doesn't auto-scroll.
- The bottom line scrolls incrementally with each character typed.
- Deleting characters from the third line reverses the scroll in the same
  increments.
- If the user manually scrolls away and starts typing again, reset — treat
  the current line as the top of the three-line zone and scroll accordingly.

## Also

When typing enough to go below the keyboard, scroll by about 3 lines at a
time, not 1.

## Source

From `android-rmail-fixes-heiepayfkvye` and `android-textbox-scroll-abcd`.

## Status

Partially shipped. Base "cursor stays visible" behavior is in;
the elaborate three-line-zone polish from the spec is deferred
because it really needs hands-on tuning to land well.

### Shipped

- Compose body now uses `TextFieldValue` so we can observe the
  cursor position via `selection.end`.
- Wrapped in a `BringIntoViewRequester` whose `bringIntoView()`
  fires whenever the cursor moves. Compose + IME insets together
  scroll the parent so the cursor's line stays visible above the
  keyboard. This is the recommended Android pattern for keeping
  text-entry visible and handles keyboard show/hide correctly.

### Deferred (would benefit from on-device tuning)

- "Cursor 3 lines above the keyboard" specifically — `bringIntoView`
  brings the cursor into view but doesn't enforce a 3-line buffer.
  Could be added by computing a line-height-aware bounding rect and
  calling the variant `bringIntoView(rect)`.
- Per-character incremental scroll inside the bottom 3-line zone
  (don't scroll until last visible line, then scroll proportionally
  per character typed).
- Manual-scroll reset of the zone.
- Below-keyboard "scroll by 3 lines, not 1" jump.

These need real-device feedback to get the line heights, keyboard
timing, and gesture detection right. The base behavior closes the
user-visible failure mode (cursor disappearing under the keyboard);
the polish layers on top.
