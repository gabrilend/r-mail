# Synced phone config

## Overview

Android clients get their own config file that syncs with the home
daemon, similar to how the contacts file syncs.

## Open question: is this actually needed?

Before committing to this, we need a concrete use case. The obvious
candidates don't hold up:

- **IP updates?** The daemon already owns its own IP; the phone doesn't
  need to set it.
- **Phone-specific settings?** Those can live on the phone alone —
  there's no desktop surface that edits them.
- **Hook-script bindings?** Explicitly ruled out by #309's
  separation principle: phone and desktop hooks are independent and
  never synced. No round-trip needed.

If no use case survives scrutiny, close this issue and remove it from
the dependency list of #309 and #310.

## Design (if we do build it)

- Separate file from the desktop config — phone-specific settings only.
- Editable on both phone and desktop; phone wins on conflict (inverse
  of contacts).
- Syncs using the same mechanism as contacts (hash comparison,
  push/pull).
- Daemon stores it alongside the mailbox (e.g. `phone-config`).
- Android app reads/writes it via new API endpoints.

## Status

Design phase — pending justification. Do not implement until a concrete
use case is documented above.
