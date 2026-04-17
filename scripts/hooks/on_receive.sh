#!/bin/sh
# on_receive — fires after a new message is written to inbox/.
#
# Runs in the background; stdout is ignored.  Args: $1 = sender,
# $2 = subject, $3 = absolute path to the saved inbox file.
#
# This is a default no-op.  Replace it, or call out from here to your
# own scripts.  See docs/scripting-tutorial.md in your rmail install
# for the full hook reference.
#
# Tip: complex sender-or-subject routing is usually cleaner as
# separate rmail mailboxes (one per purpose) than as branching inside
# a single hook.

exit 0
