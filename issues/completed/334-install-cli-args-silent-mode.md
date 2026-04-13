# #334 — Install script: accept all interactive inputs as CLI arguments

## Problem

Every value the install script needs is gathered through an interactive
prompt. There's no way to run the installer unattended (e.g. from a
configuration-management script or a USB-stick bootstrap).

## Requirements

- Each interactive question (name, port, mail directory, etc.) accepts a
  corresponding command-line flag or environment variable.
- When a value is supplied via CLI/env, the matching prompt is skipped
  entirely — not even shown as "default = X". The installer proceeds
  silently for that step.
- If every required value is supplied, the installer runs with no
  prompts at all.

## Source

From `issues/new-issue-please-sort`.
