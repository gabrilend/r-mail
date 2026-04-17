# #341 — Install script: remove the "AES-256-GCM encryption is active" line

## Problem

The installer prints `AES-256-GCM encryption is active - no configuration
needed`. It's reassurance noise that doesn't help the user and clutters
install output.

## Fix

Delete the line from install output.

## Source

From `issues/new-issue-please-sort`.
