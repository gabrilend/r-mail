#!/bin/sh
# on_consent — fires when a contact asks to send you an attachment, just
# after its consent form is written to inbox/.
#
# Runs to completion before rmail answers the sender, so keep it quick.
# Args: $1 = sender, $2 = file name (as the form shows it), $3 = absolute
# path to the consent form, $4 = absolute path to the inbox file of the
# message the attachment belongs to ("" when that message is not in the
# inbox), $5 = expected size in bytes.
#
# Print "accept" or "deny" to answer the form for yourself; print nothing
# to leave the form waiting for you, as it would without this hook.
#
# This is a default no-op: every form waits for you.  Replace it, or call
# out from here to your own scripts.  See docs/scripting-tutorial.md in
# your rmail install for the full hook reference.

exit 0
