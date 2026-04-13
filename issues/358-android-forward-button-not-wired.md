# #358 — Forward button in ReadScreen is a no-op

## Problem

Viewing an inbox message shows a "Forward" item in the overflow
(three-dots) menu. Tapping it does nothing visible — the callback is
wired to an empty lambda in `MainActivity.kt`:

```kotlin
ReadScreen(
    ...
    onReply = {}, onForward = {}
)
```

`ReadScreen.kt` already has a `buildForward(msg)` helper that quotes
the message body with `| ` prefixes (classic forward style) and
seeds a `to: ` header. The wiring to the compose screen is missing.

## Intended behavior

Tapping Forward should:

1. Switch to the Write panel.
2. Pre-fill the composer with the quoted body `buildForward(msg)`
   produced (currently: `to: \n\n\n\n| <each-line>`).
3. Pre-fill the subject with a "Fwd: " prefix on the original subject
   — or similar. The original outbox note on this says "a 'forwarded'
   suffix or something, I forget." Pick a convention:
   - **Prefix `Fwd: `** — matches classic email, reads left-to-right,
     users recognise it.
   - Suffix `(fwd)` — shorter but unusual.
   Recommendation: `Fwd: <original subject>`. Avoid stacking on
   repeated forwards (strip a leading `Fwd:` before re-applying).
4. Leave the recipient field empty so the user can pick who to send to.

## Scope notes

- `onReply` is also wired to `{}` in `MainActivity.kt`. Worth fixing
  in the same pass: reply opens the Write panel pre-addressed to
  the sender with subject `Re: <orig>` and the quoted body (same
  `buildForward` style, or a separate `buildReply` that omits the
  quote depending on preference).
- The composer already accepts pre-filled draft state via `draftSubject`,
  `draftBody`, `draftRecipients` in `InboxScreen.kt` — so hooking up
  Forward is mostly about routing those values from `MainActivity`
  callbacks into the `InboxScreen`'s state.

## Source

From `issues/android-123`.

## Status

Not started.
