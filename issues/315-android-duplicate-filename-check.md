# #315 — Prevent duplicate filenames in outbox

## Problem

If a user sends a message with the same subject as an existing outbox file,
the spaces-to-dashes filename conversion could collide with an existing file.
The duplicate needs to be caught after conversion, not before.

## Requirements

- On the daemon side: if a delivered file would have the same filename as an
  existing inbox file at the destination, reject delivery (or rename).
- On Android: if the user composes a message whose converted filename matches
  an existing outbox file, prevent it from entering the outbox.
- The duplicate check must happen on the **converted** filename (after
  spaces-to-dashes and any other normalization), not the raw subject.

## Source

From `android-rmail-fixes-heiepayfkvye`.
