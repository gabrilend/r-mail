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
