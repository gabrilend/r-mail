#!/bin/sh
# on_receive_raw — fires before a new message is written to inbox/.
#
# Synchronous.  Args: $1 = sender  $2 = subject  $3 = message body
# (empty when over 64 KiB).  The whole body is on stdin: read it with
# body=$(cat).  stdout replaces the saved body; empty output keeps it.
# A non-zero exit, or a hook that cannot run, refuses the message: the
# sender's daemon sends it again later (#215).
#
# This is a default pass-through.  Replace it, or call out from here
# to your own scripts.  See docs/scripting-tutorial.md in your rmail
# install for the full hook reference.
#
# Tip: complex sender-or-subject routing is usually cleaner as
# separate rmail mailboxes (one per purpose) than as branching inside
# a single hook.

exit 0
