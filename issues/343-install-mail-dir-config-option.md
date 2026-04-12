# #343 — Install script: mail directory option not written to config

## Problem

The install script does not properly create the mail-directory entry in
the generated config file. The value the user enters at the prompt is
collected but the corresponding line is missing (or malformed) in the
resulting config.

Additionally, when the user manually adds the mail-directory line to the
config and re-runs the installer, the existing value is not picked up as
the default shown in the `[ ]` brackets of the prompt.

## Fix

- Ensure the mail-directory key is written to the config with the value
  collected from the prompt.
- When re-running the installer, parse the existing config and use the
  current mail-directory value as the default for the prompt.

## Source

From `issues/new-issue-please-sort`.
