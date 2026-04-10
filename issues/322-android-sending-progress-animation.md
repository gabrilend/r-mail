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
