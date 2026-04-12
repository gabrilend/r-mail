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

## Source

From `issues/new-issue-please-sort`.
