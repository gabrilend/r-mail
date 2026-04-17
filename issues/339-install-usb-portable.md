# #339 — Install script: make installer runnable from a USB drive on all OSes

## Problem

Users should be able to carry the installer on a USB stick and run it
against a freshly set-up machine without needing network access or a
pre-configured environment. Right now the installer assumes a normal
developer shell environment and is shell-specific.

## Requirements

- Bundle (or provide sibling bundles of) the dependencies the installer
  needs.
- Ensure the installer works from a read-only/removable mount
  (don't write into the script's own directory).
- Provide a cross-platform entry point: at minimum Linux, macOS, and
  Windows (WSL or a native wrapper).

## Notes

Overlaps with #334 (CLI-arg silent mode) — running from a USB likely
means running non-interactively.

## Dependencies

Blocked on the per-platform thin clients being functional. Each
platform's USB-portable installer wraps the corresponding
`clients/<platform>/install-thin-client-<platform>.sh`, so until the
thin client itself works end-to-end for that platform, there's nothing
the installer can hand off to. Current state:

- **Android** — app exists under `clients/android/` and is functional.
  Ready for inclusion in a USB bundle once a bundling story is
  decided (APK file + sideload instructions is the obvious start).
- **Linux** — `clients/linux/` scaffolding exists; thin client not
  yet complete. The daemon (home server) installer already works on
  Linux, so the "home server on Linux" half of this issue can be
  closed out independently if we want to scope that narrowly.
- **macOS** — `clients/macos/` scaffolding exists; thin client not
  yet complete. Blocked.
- **Windows** — `clients/windows/` scaffolding exists; thin client
  not yet complete. Blocked.

Acceptance for full closure: at minimum Linux and Android thin clients
shipped; the other two either shipped or explicitly scoped out.

## Source

From `issues/new-issue-please-sort`.
