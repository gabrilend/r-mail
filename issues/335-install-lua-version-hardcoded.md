# #335 — Install script: reports hardcoded Lua version instead of the actual one

## Problem

When a Lua newer than 5.4.8 is present on the system, the installer still
prints `lua 5.4.8 found`. The version string is hardcoded rather than
read from the discovered interpreter.

## Fix

Query the actual interpreter (`lua -v` or equivalent) and print the
version it returns.

## Source

From `issues/new-issue-please-sort`.
