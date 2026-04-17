# #314 — Android third-party app outbox access security

## Problem

If we add FileObserver-based auto-sync on Android outbox directories, any app
with access to those directories could write a file that gets automatically
encrypted and sent to the home daemon as a trusted message. The daemon has no
way to distinguish "written by rmail app" from "written by malicious app."

## Current state

Right now, outbox writes only happen through our own code (Compose screen ->
MainViewModel.saveOutboxFile -> MailStore.writeOutbox). The triggerSync() call
is in MainViewModel, not in a filesystem watcher, so only our UI can trigger
sends.

## Security model

All traffic sent to the home daemon must originate from:
- Our own app code
- Our own editor (compose screen)
- Our own mailboxes

## Future investigation: third-party app integration

If we ever want to allow other Android apps to compose rmail messages (e.g.
share intents from other apps, automation tools, scripts), we need a secure
channel:

Ideas to explore:
- **ContentProvider with signature-level permissions** — only apps signed with
  our key can write, but this blocks all third-party use
- **Intent-based API** — third-party apps send an Intent to rmail, which shows
  a confirmation dialog before writing to outbox. User sees exactly what will be
  sent before it goes out
- **Pending outbox / quarantine** — third-party writes go to a staging area,
  user must approve each one in the rmail UI before it enters the real outbox
- **Per-app tokens** — rmail issues a token to authorized apps, messages include
  the token so the user can audit which app sent what

The Intent + confirmation dialog approach is probably the right starting point:
it requires no filesystem access, works with Android's security model, and gives
the user a clear approval step.
