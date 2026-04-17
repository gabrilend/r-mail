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

Closed 2026-04-14 (second pass). Floor shipped and verified on-device.
Polish items 3/4/5 parked — revisit if the feel warrants it.

### History

Reopened 2026-04-14 — the "base" behavior we thought was shipped was
itself broken on-device (viewport shifted ~half a line on the first
wrap then stopped). Fixed by switching the `BringIntoViewRequester`
call from bare `bringIntoView()` (which used the whole 300dp textbox
as its target and gave up once any sliver was visible) to
`bringIntoView(caretRect inflated by 3 line-heights below)` using
`TextLayoutResult.getCursorRect(offset)`.

### Shipped this pass

- Caret lands ~3 lines above the keyboard rather than just "visible."
- Continued typing doesn't scroll until the caret reaches the last
  visible line (the buffered rect fits until then).
- Wrap-down shifts the viewport by roughly a line at a time — no more
  half-line stalls.

### Parked (revisit if feel warrants)

- Per-character proportional scroll across the bottom line (horizontal
  caret motion drives a pixel-per-char slide so the line ends up
  third-from-bottom by the time you hit the right margin).
- Delete reverses the per-character scroll in the same increments.
- Manual-scroll reset: if the user swipes the viewport away from the
  caret, resuming typing re-anchors from where they scrolled to rather
  than snapping back.

These three together need a small state machine and gesture detection
and are the reason the spec originally called out "needs hands-on
tuning." The floor covers the user-visible failure mode.

### What's wired today

- Body editor uses `TextFieldValue`, so `selection.end` is observable
  (`clients/android/.../InboxScreen.kt` around line 1585).
- A `BringIntoViewRequester` is attached to the `BasicTextField`'s
  modifier, and a `LaunchedEffect(bodyValue.selection.end)` calls
  `cursorRequester.bringIntoView()` every time the cursor position
  changes.
- The parent `Column` uses `verticalScroll(scrollState)` and is the
  scrollable ancestor `bringIntoView` is expected to drive.

### Observed on-device (2026-04-14)

- When typing wraps to a new line the first time, the viewport shifts
  down **once** but only ~half a line — the new line is only partially
  visible and the cursor sits at the very bottom edge.
- On every subsequent wrap, the viewport does not shift at all. The
  cursor walks straight off-screen and disappears behind the keyboard.
- The requester plumbing is live (the initial half-line shift proves
  that) but it is not producing enough scroll to keep pace with
  continued typing.

### Hypotheses to investigate

1. `bringIntoView()` is being called with the caret's bounding rect,
   which is effectively zero-width and one line tall. Once the caret
   sits at the bottom of the viewport, the rect is *just barely*
   inside the visible region — so the requester thinks the job is done
   and refuses to scroll further. Need an **inflated rect** that
   includes several line-heights of context *below* the cursor, so the
   requester is obligated to leave breathing room.
2. IME-inset-driven scroll only runs on keyboard show/hide, not on
   keystrokes, so it can't help as typing continues.
3. `onFocusChanged { scrollState.animateScrollTo(bodyYOffset) }` only
   fires on focus transitions and doesn't re-assert while typing.

### Desired behavior (original spec — still the target)

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

### Next step

Fix the floor ("cursor stays visible with a buffer") first — the
per-character polish can stack on top once the floor is solid. The
simplest floor fix is likely to replace the bare `bringIntoView()` call
with a rect that extends a few line-heights *below* the caret, forcing
the requester to scroll until that buffer fits in the viewport.
