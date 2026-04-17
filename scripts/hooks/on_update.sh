#!/bin/sh
# on_update — fires when a living message (see issue #306) is updated.
#
# Synchronous.  Args: $1 = sender, $2 = absolute path to the inbox
# file that still holds the old body, $3 = the new body just arrived.
# stdout replaces the saved body; empty output or non-zero exit
# applies the update as-is.
#
# This is a default pass-through.  Replace it, or call out from here
# to your own scripts.  See docs/scripting-tutorial.md in your rmail
# install for the full hook reference — note the periodics pattern
# at the end uses this hook.
#
# Tip: complex routing is usually cleaner as separate rmail mailboxes
# (one per purpose) than as branching inside a single hook.

exit 0
