#!/bin/sh
# on_package — fires after a received attachment is fully assembled
# and saved.
#
# Runs in the background; stdout is ignored.  Args: $1 = sender,
# $2 = filename (useful for filetype detection), $3 = absolute path
# to the saved attachment file, $4 = absolute path to the inbox file of
# the message it came with ("" when that message is no longer in the
# inbox).
#
# This is a default no-op.  Replace it, or call out from here to your
# own scripts.  See docs/scripting-tutorial.md in your rmail install
# for the full hook reference.
#
# Tip: complex routing is usually cleaner as separate rmail mailboxes
# (one per purpose) than as branching inside a single hook.

exit 0
