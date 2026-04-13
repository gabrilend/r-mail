#!/bin/sh
# on_delete — fires when a message is deleted from inbox or outbox.
#
# Synchronous; stdout is ignored.  Args: $1 = the name of the other
# party (sender for inbox deletions, recipient for outbox deletions).
#
# This is a default no-op.  Replace it, or call out from here to your
# own scripts.  See docs/scripting-tutorial.md in your rmail install
# for the full hook reference.
#
# Tip: complex routing is usually cleaner as separate rmail mailboxes
# (one per purpose) than as branching inside a single hook.

exit 0
