# #340 — Install script: write the config file as soon as required fields are collected

## Problem

The installer gathers all inputs, does all of its setup, and then writes
the config file at the end. If anything fails mid-run, the user has
entered values that are now lost.

## Fix

As soon as the installer has enough information to write the config
(name, port, mail directory, and any other required fields), commit the
config file to disk. Later steps can then amend it but don't block
persistence of the already-entered values.

## Open question

Confirm the minimum required field set. Current guess: name, port, mail
directory. Audit the install script to check for anything else that must
be set before the daemon can start.

## Source

From `issues/new-issue-please-sort`.
