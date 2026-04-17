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

## Status

Shipped. Both sides now guard against the collision on the converted
filename, not the raw subject.

### Daemon (`rmail.lua`, `handle_deliver_message`)

The existing branch for "different sender, same subject" stays —
that case is disambiguated with a `-from-<sender>` suffix. Added a
new branch for **same sender, same sanitised subject, different
message_id**: appends a short (≤ 6 hex chars) slug derived from
the new message_id to the filename. Numeric fallback (`-2`, `-3`…
up to `99`) if even that collides. The "same sender, same subject,
same message_id" case continues to hit the early return that
treats it as "more attachments for the existing message" — that
wasn't the bug.

### Android (`InboxScreen.kt`, Send button)

Before writing the outbox file, the Send handler sanitises the
subject and checks `vm.outboxFiles.value.contains(filename)`. If
it hits, it pops an AlertDialog ("Subject already in outbox") with
**Cancel** (preserve the draft, let the user tweak the subject)
and **Replace** (deliberate overwrite of the existing outbox
file). The raw subject isn't checked; the converted-filename check
catches `hello world` and `hello-world` both reducing to
`hello-world` before they overwrite each other on disk.

### Test points covered

- Same-sender repeat sends on the daemon side: disambiguated, not
  overwritten.
- Subject with spaces vs hyphens on the Android side: both produce
  the same converted filename and both trigger the warning.
- Draft is preserved when the dialog appears — user doesn't lose
  what they typed.
