# #359 — Replace the confusing top-left back arrow with a tappable mailbox title

## Problem

The top bar in the mailbox view shows a `←` back arrow on the left and
the mailbox name (as plain text) in the title slot. The arrow is
confusing: it looks like it should take you to the *previous* screen
you were on, but it actually takes you back to the mailbox list —
regardless of where you came from. That mismatch between visual
affordance ("back") and actual behavior ("go to mailbox list") trips
users up.

## Proposed fix

- **Remove the back-arrow IconButton** from the mailbox top bar.
- **Make the mailbox-name title tappable.** Same physical target
  region (top-left area of the top bar), same destination (mailbox
  list), but the affordance now reads as "here's what mailbox I'm
  in; tap to switch" rather than "here's back."

A tap on the title already puts the finger in the same place as the
back arrow, so muscle memory is preserved. What changes is the user's
mental model — no arrow means no false promise about "previous
screen."

## Edge cases

- The contact-editor sub-view inside the Contacts panel currently uses
  the same arrow, with a different action ("back to contacts"). That's
  a legitimate "back one step" action and should **keep** the arrow —
  the arrow affordance matches the behavior there.
- Any screen where we want true "back one step" behavior keeps the
  arrow. The only replacement is in the top-level mailbox view where
  "back" really means "switch to the mailbox list."

## Implementation notes

- Most of the work is in `InboxScreen.kt` where the top bar is
  defined. The `navigationIcon` slot currently holds an `IconButton`
  with `Icons.AutoMirrored.Filled.ArrowBack`; replace with empty /
  no icon, and make the title `Text` `clickable { onBack() }`.
- Visual polish: a very subtle underline or ripple on tap would
  signal "interactive text" without adding visual weight.

## Source

From `issues/android-123`.

## Status

Shipped.

- `InboxScreen`'s `navigationIcon` slot is empty when at the
  mailbox top level; the back arrow only appears in the
  contact-editor sub-view (where "back one step" matches the
  visual affordance).
- The mailbox-name title is now rendered with
  `TextDecoration.Underline` and a `clickable { onBack() }`
  modifier. Tapping it navigates to the mailbox list — same
  destination as the old arrow, same physical tap target.
- No change to the Contact editor back-arrow or to any other
  screen's `← arrow` affordance.
