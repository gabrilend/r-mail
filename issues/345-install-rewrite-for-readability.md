# #345 — Rewrite install script for readability

## Problem

The current bash installer relies on heavy shell idioms and is hard to
read at a glance. For users installing unknown software, the installer
is the first thing they'll inspect — hard-to-read code undermines trust.

## Design

Rewrite the installer in a style that reads like plain programming
rather than shell tricks: explicit variables, named helpers, and linear
flow. Bash is still the best choice for the outermost entry point since
it ships on every target platform, but the bulk of logic should be
expressed as readable functions.

Rewriting in Lua was considered, but the installer has to run on
machines that don't yet have a Lua interpreter, so bootstrapping Lua is
itself a chicken-and-egg problem. Staying in bash (or POSIX sh) for the
outer shell, while keeping it readable, is the pragmatic path.

## Non-goals

No change in installer behavior — this is a code-organization and
readability improvement only.

## Source

From `issues/new-issue-please-sort`.
