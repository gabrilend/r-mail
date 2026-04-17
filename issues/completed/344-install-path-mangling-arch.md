# #344 — Install script: config file paths mangled (slashes → dashes with escapes)

## Problem

On an Arch Linux test system, the installer wrote file paths into the
config with slashes replaced by dashes and stray backslashes inserted.
The same install runs fine on another Linux system without this
mangling.

The distribution difference alone should not matter — the installer does
not use anything distro-specific — so this is likely a quoting or
variable-expansion bug that happens to surface under a particular shell
environment.

## Investigation

- Reproduce on Arch with a clean home directory.
- Diff the generated config against a known-good one from a working host
  to see exactly which fields are being transformed and how.
- Suspect areas: `sed` substitutions, heredoc escaping, and any use of
  `printf`/`echo -e` on path values.

## Fix

Quote path values uniformly and avoid running them through sed patterns
that treat `/` as a delimiter.

## Source

From `issues/new-issue-please-sort`.

## Status

Completed (to the extent the code can be hardened without a reproducer).

- **"Slashes replaced with dashes"**: this is the **intentional
  `CONFIG_SLUG` behavior** — the config filename
  `~/.config/rmail/config-home-ritz-mail` reflects the mail path so
  each mailbox has its own config. The install script now has a
  comment explaining this so it's not read as mangling on next
  review.
- **"Added backslashes weirdly"**: not reproducible from a code read,
  but the likely source was the docs-template `sed` step using
  `$MAIL_DIR` unescaped as a replacement. If the path contained `|`,
  `\`, or `&`, sed would either fail outright or emit a mangled
  value. Both the docs-template generation and the config update path
  now route replacement values through a new
  `sed_escape_replacement` helper (doubles `\`, escapes `|` and
  `&`). The config update path itself no longer uses sed at all — it
  goes through `set_config_value` (awk), so path content is never
  touched by an escape layer.
- **Defense in depth against future regressions**: any future code
  that writes paths into the config should use `set_config_value`;
  any future sed-based template substitution should route replacement
  values through `sed_escape_replacement`.

If the user ever reproduces the specific backslash artifact again,
that reproducer goes into this issue's problem section and we reopen.
