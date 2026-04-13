#!/bin/sh
# on_send — fires once per recipient just before a message is sent.
#
# Synchronous; called separately for each recipient with fresh args.
# Args: $1 = recipient, $2 = subject, $3 = message body as it will
# be sent to that recipient.  stdout replaces the body for that
# recipient only; empty output or non-zero exit sends the original
# body unchanged.
#
# This is a default pass-through.  Replace it, or call out from here
# to your own scripts.  See docs/scripting-tutorial.md in your rmail
# install for the full hook reference.
#
# Tip: complex per-recipient transformations are often cleaner as
# separate rmail mailboxes (one per audience) than as branching
# inside a single hook.

exit 0
