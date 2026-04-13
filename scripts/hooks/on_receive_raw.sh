#!/bin/sh
# on_receive_raw — fires before a new message is written to inbox/.
#
# Synchronous.  Args: $1 = sender  $2 = subject  $3 = message body.
# stdout replaces the saved body; empty output or non-zero exit
# leaves the original body as the sender sent it.
#
# This is a default pass-through.  Replace it, or call out from here
# to your own scripts.  See docs/scripting-tutorial.md in your rmail
# install for the full hook reference.
#
# Tip: complex sender-or-subject routing is usually cleaner as
# separate rmail mailboxes (one per purpose) than as branching inside
# a single hook.

exit 0
