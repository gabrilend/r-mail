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

## Status

Completed.
- Config template now includes a `mail = <path>` line alongside `name`
  and `port`.
- Install-script re-runs read the existing `mail` value and use it as
  the default shown in the `[brackets]` of the mail-directory prompt.
- Update path replaced brittle sed substitutions with a new
  `set_config_value` awk helper that appends the key if missing and
  rewrites in place otherwise — works for any path content, no escape
  gymnastics.
- Daemon still takes the mailbox path from the command line (via the
  service file). The config `mail` field is a record for tooling and
  the installer; wiring the daemon to prefer it over argv is a
  separate piece of work if we want it.
