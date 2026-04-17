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

Shipped. Reply wired up in the same pass.

- `ReadScreen`'s `onReply` / `onForward` callback signatures now
  carry `(sender, subject, body)` / `(subject, body)` respectively,
  with body being the `| `-quoted content from the old
  `buildReply`/`buildForward` helpers (consolidated into a single
  `buildQuoted`).
- `MainViewModel.senderOfInbox(filename)` looks up the sender from
  `sync-state.inbox`.
- `MainActivity`'s NavHost wires both callbacks to
  `vm.queuePendingDraft(...)` and `navController.popBackStack()`:
    - **Reply** — `recipients = listOf(sender)`,
      `subject = "Re: " + original` (existing `Re:`/`Fwd:` prefix
      stripped to avoid stacking).
    - **Forward** — `recipients = listOf("")`,
      `subject = "Fwd: " + original` (same dedup).
    - On the outbox `ReadScreen`, Reply is a no-op (you don't
      reply to your own outgoing messages); Forward behaves the
      same as the inbox forward.
- `MainViewModel.pendingDraft: StateFlow<PendingDraft?>` is
  observed by `InboxScreen`; a `LaunchedEffect` fills
  `draftRecipients` / `draftSubject` / `draftBody`, switches
  `currentPanel` to `WRITE`, and calls
  `vm.consumePendingDraft()` so bouncing between panels doesn't
  re-populate.
