# #360 — Move the message filename out of the top bar and into the message body

## Problem

In the Android message view (`ReadScreen`), the selected message's
filename is rendered as the `TopAppBar` title (`ReadScreen.kt` around
line 79: `title = { Text(filename) }`). When the filename is long, the
top bar truncates or scrolls it in an awkward way, and the user can
never see the whole name.

The top bar is a fixed-width container, so trying to fit an arbitrary
filename into it will always fight the surrounding iconography.

## Proposed fix

- **Remove the filename from the `TopAppBar` title slot.** The top bar
  can either go title-less or show something stable (e.g. the mailbox
  name) — to be decided during implementation.
- **Show the filename as the first line of the message body** instead,
  in the same scrollable monospace container the body uses. The body
  container already wraps at `readerColumns` and respects the user's
  zoom, so a long filename behaves like any other long line of text.

## Important: this is presentation-only

The injected filename line is **Android UI sugar only**. It must not:

- be written back to the stored inbox/outbox file,
- be uploaded on sync,
- appear when the message is viewed on the desktop/daemon side,
- be included in Reply / Forward body quoting (so we don't leak the
  local filename into outgoing messages).

Treat it purely as a prefix rendered at view time. The underlying
`MailMessage.content` is unchanged.

## Implementation notes

- `ReadScreen.kt` is the only file that should need changes. The
  filename is already passed in as a parameter.
- Prepend the filename (plus a blank line separator, or whatever looks
  right in monospace) in the composable that renders the body — not in
  the model layer.
- Double-check the Reply/Forward body-builders (`buildReply`,
  `buildForward` in the same file) consume `msg.content`, not the
  rendered string. If they touch the rendered string, they'd need to
  be adjusted to strip the prefix — easier to make sure they keep
  using `msg.content` directly.
- Outbox view (`isOutbox = true`) should get the same treatment for
  consistency.

## Edge cases

- Very long filenames still need to behave — because they now live in
  the monospace body container, they wrap at `readerColumns` like any
  other line. That's the whole point.
- Consent messages (`msg.isConsent`) have their own rendering path;
  decide whether the filename prefix should appear there too.

## Source

User request 2026-04-14.

## Status

Open.
