# Android: fix scroll behavior when typing long messages

## Current behavior

When typing long messages on Android, the keyboard covers part of the
text input area. The user cannot see the bottom of their message while
typing.

## Intended behavior

When the keyboard is open, the text input should scroll so the cursor
(and recently typed text) is always visible above the keyboard.

The user should be able to see what they're typing at all times.

## Suggested implementation steps

1. Review the compose message screen in the Android client
2. Ensure the TextField/input area adjusts for keyboard insets
3. Test with long messages to verify scroll behavior
4. Consider: should the view auto-scroll to cursor position on each keystroke?

## Related files

- Android client compose screen (Kotlin/Compose)
- issues/305-expand-android-client.md (general Android improvements)

## Source

Mail: ~/mail/inbox/r-mail-improvements (line 7) — file processed and removed
