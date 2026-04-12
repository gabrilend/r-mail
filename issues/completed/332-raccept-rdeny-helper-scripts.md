# #332 — raccept / rdeny helper scripts: respond to package requests

## Problem

When a contact sends an attachment, a consent file appears in the inbox
(e.g. `photo-consent-to-download-form`). The user must manually edit the
file to delete either the `accept` or `deny` line. There's no way to
automate this from hook scripts.

## Design

Two shell scripts that accept or deny package consent requests:

- `helpers/raccept.sh <consent-file>` — removes the `deny` line, leaving
  only `accept`.
- `helpers/rdeny.sh <consent-file>` — removes the `accept` line, leaving
  only `deny`.

The consent file is the path to the inbox file (the one ending in
`-consent-to-download-form`). The daemon's `check_consent_pending()` picks
up the decision on the next sync cycle.

### Usage from hook scripts

Users can wire these into `on_receive` hooks for automatic accept/deny
logic:

```sh
# on_receive hook: auto-accept from alice, deny from gary
sender="$1"
file="$2"

case "$file" in
    *-consent-to-download-form)
        case "$sender" in
            alice) helpers/raccept.sh "$file" ;;
            gary)  helpers/rdeny.sh "$file" ;;
        esac
        ;;
esac
```

## Source

From `issues/addresser`.

## Status

Completed. Implemented as `helpers/raccept.sh` and `helpers/rdeny.sh`,
documented in `docs/helper-scripts.md`.
