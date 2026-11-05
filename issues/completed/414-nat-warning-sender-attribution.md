# NAT warning message should identify sender

## Status

Closed 2026-11-05 with nothing built: superseded by #411.  The warning
this issue would reword no longer exists.  Since 2026-10-08 the daemon
does not check the router and writes nothing to contacts about it; the
installer's check is the only one, and it tells only the person
installing, about their own router.  See the decisions below.

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

## Decisions (2026-11-05)

Made by the builder; the owner can overturn each.

1. **Nothing to build.**  The owner, 2026-10-08 (#411): "we don't want
   to do it on startup", and contacts warned by an earlier run "are told
   nothing more".  Naming the sender in a warning that is never sent
   would bring back a message the owner removed, so the issue is closed
   rather than built.  Its source mail (a warning that did not say who
   sent it) is answered by the removal: no contact receives one now.
2. **If a warning to contacts ever comes back**, the three points above
   are its requirements: it names the sending mailbox by its own name for
   itself in the subject and the body (#506 is about how a mailbox
   states that name), it says "do
   not send me anything sensitive until this is fixed" first and the
   technical cause after, and it says plainly that the problem is the
   sender's router, not the reader's.  Recorded here so the issue that
   revives it starts from them.
3. **The installer's warning already meets points 1 and 3** for its one
   reader: it speaks to the person installing about "your router".  It
   is left as it is.
4. **Stale words fixed with this closing**: the comment above
   `report_problem` in `rmail.lua` no longer speaks of "the existing
   router-security warning" (there is none); #413's action no longer
   promises a "resolved" message to contacts; #826's list of issues that
   would hurt a first run drops #414.

## Related files

- rmail.lua (security check logic)
- issues/completed/413-disable-nat-pmp-on-router.md (context)

## Source

Mail: ~/mail/inbox/insecure-nat-missing-from-tag — file processed and removed
