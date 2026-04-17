# #322 — Animated sending progress notification on Android

## Problem

After sending from Android, there's no visual feedback about delivery status.

## Desired behavior

- Green notification bar slides along the top: "sending..."
- A progress bar of dots counts down to the next sync cycle — one dot per
  second, room for 30 dots.
- Dots disappear in random order, but the last 3 disappear last.
- In the final 3 seconds, the last 3 dots slide off the right edge.
- "sending" text becomes:
  - "sent" — if delivered successfully
  - "ready" — if the recipient is offline or the daemon is unreachable

## Source

From `rmail-upon-sending`.

## Status

Shipped. Design tweaked slightly from the original spec to match the
app's actual sync cadence.

### What landed

- New `SendingProgressBar` composable in `InboxScreen.kt`, rendered
  just below the error box at the top of the main content column.
- `MainViewModel.SendingBar` state (`startedAtMs`, `outboxFilename`),
  set by `markSendingStart()` when the Send button fires; cleared
  after the animation settles.
- **15 dots** rather than 30. The phone's foreground-sync cadence is
  short (inotify on the outbox means most sends settle in a second
  or two), so 15 dots at 5/s (~3 s) is enough to make the animation
  land before the sync actually completes.
- Non-tail dots fade out in random order (tick every 200 ms), one
  per tick, picked from positions `0..11`. The last 3 dots are
  reserved: they stay lit until the sync settles.
- When `syncStatus` transitions to `IDLE` (success) or `ERROR`
  (offline/unreachable), the last 3 dots **slide off the right
  edge** over ~550 ms with 120 ms staggered delays. The row is
  `clipToBounds()` so they physically leave the visible area
  rather than drifting beyond the bar.
- Text: `"sending…"` during the countdown, then `"sent"` on IDLE
  or `"ready"` on ERROR. "sent" auto-dismisses after 1.5 s; "ready"
  stays visible (so the user knows the message is queued locally)
  until they act on it or trigger the next sync manually.

### Tradeoffs vs the original spec

- **30 dots → 15 dots.** 30 was sized for a 30-second sync cycle;
  the phone's cadence is much shorter. 15 feels like the animation
  is dancing with the sync rather than dragging through it.
- **1 dot/sec → 5 dots/sec.** Same reason — keep the visual action
  aligned to real sync time without dropping below one frame of
  animation.

Everything else (random disappearance, last 3 reserved, slide-off
exit, success/failure text) matches the original spec.
