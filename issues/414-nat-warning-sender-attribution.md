# NAT warning message should identify sender

## Current behavior

Since 2026-10-08 (#411) rmail sends no such warning at all: the daemon no
longer checks the router at start-up, and the installer's check reports
only to the person installing.  Nothing is left for this issue to change
unless a warning to contacts comes back.

Before that: when rmail detected insecure NAT-PMP/UPnP on a sender's
router, it sent a warning to contacts. However, the warning message didn't
identify who sent it — recipients saw the warning but didn't know which
contact had the security issue.

## Intended behavior

The insecure NAT warning message should:
1. Clearly identify the sender (whose router has the issue)
2. Emphasize the "don't send me sensitive information" angle
3. Make it clear this is about the sender's network, not the recipient's

## Suggested implementation steps

1. Locate the security warning message generation in rmail.lua
2. Include sender name in the message subject or body
3. Reword the warning to focus on "sensitive info risk" rather than technical details
4. Test with a contact to verify the message is clear

## Related files

- rmail.lua (security check logic)
- issues/completed/413-disable-nat-pmp-on-router.md (context)

## Source

Mail: ~/mail/inbox/insecure-nat-missing-from-tag — file processed and removed
