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
