# #338 — Install script: wrongly implies "your name" is shown to contacts

## Problem

During install the prompt for the user's name suggests that the value
will be displayed to their contacts. In reality, contacts see the local
name the recipient assigns to them — the installer's "your name" field
is not transmitted.

## Fix

Reword the prompt so it accurately describes where the name is used
(local identification, logs, etc.) and does not claim it's shown to
other people.

## Source

From `issues/new-issue-please-sort`.
