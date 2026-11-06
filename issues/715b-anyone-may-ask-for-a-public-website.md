# #715b — Anyone may ask for a public website

Sub-issue of #715.  Needs #715a.

## Current Behavior

*Built 2026-11-06* (see Status, and the decisions at the end):
`website_access = public` lets anyone fetch the website with
`run-rmail.sh <their config> --website=<host>:<port>`.  Before that, only
contacts could ask (#715a).

## Intended Behavior

With `website_access = public`, anyone may ask for the website, not only
contacts.  The owner (2026-10-13): "If the server is private, then no
stranger can request the website. If the website is public, they just
have to send a plain HTTP request."  The way in named: an rmail Firefox
plugin.

### The owner's proposal: timing as a tamper check

The owner's design (2026-10-13), in their words:

> The sender will encrypt the file with a random token, and provide it to
> the receiver who can decrypt the file to validate that it's theirs.
> However it will add the decryption steps that adds like 10 seconds or
> whatever, a certain amount of extra depending on how fast the latency
> is between them. … the receiver and the sender can both be messaging
> back-and-forth in a parallel channel while the process is ongoing. If
> an attacker wanted to replace the file, they'd have to take it, unlock
> it, modify it, then provide it to the receiver. But... if we're talking
> and communicating and we can determine exactly how long it takes to
> decrypt the message, then we can know if there's any disruptions. Like…
> if we're happily sending back and forth at 15ms per packet … then we
> send an attachment packet and it takes 30ms to receive but it should be
> the same size and shape... then we know it's fraudulent. … What do you
> think? Verifiable security?

### Assessment, given to the owner 2026-10-13

The puzzle the proposal uses is a real thing: a *time-lock puzzle*
(Rivest, Shamir and Wagner, 1996) is a lock whose opening takes a known
amount of work that has to be done one step after another, so adding
more processors does not speed it up.  Timing is also a real security
tool: *distance bounding* protocols use how long a reply takes to prove
how far away the other side is.

Against an attacker in the middle of a first contact, timing does not
hold, for three reasons:

1. **The attacker does not need to open the real file.**  They can
   prepare their own file, locked with their own random token, before
   the conversation starts, and hand it over at the same moment the real
   one would have arrived.  No extra delay appears.
2. **The baseline is theirs too.**  If the attacker sits in the middle
   from the first packet, every 15 ms measured already includes them.
   There is no clean timing to compare against.
3. **Networks wobble by more than the margin.**  A packet that usually
   takes 15 ms takes 30 ms whenever Wi-Fi retries or a router queue
   fills.  The check would raise false alarms all day, or be loosened
   until it misses real ones.

The underlying rule: two parties who share nothing beforehand (no key, no
trusted third party, no channel the attacker cannot touch) cannot tell an
attacker in the middle apart from each other.  Every working system adds
one of those things.  HTTPS adds certificate authorities.  SSH trusts the
first key it sees and warns if it ever changes.  Signal shows two people
a "safety number" to compare in person.

Where the owner's timing idea does work: proving that **a device you
already know** is running the code you expect.  It is "software-based
attestation" (SWATT, 2004; Pioneer, 2005): a checker sends a fresh
challenge, the device computes a checksum over its own memory, and an
answer that is right but late means some other code had to fake it.
That fits the base-station idea for the Soren DS handhelds better than
it fits strangers.

## Open questions

1. **Which way in for strangers?**  Options, most likely to work first:
   (a) *trust on first use*, as SSH does: the first website from an
   address is accepted and its key remembered, and a later change is
   refused loudly; (b) the same, plus a short string of words or emojis
   shown on both sides, compared by the two people some other way (in
   person, by phone), as `handheld-office`'s emoji pairing does; (c) the
   owner's timing check, kept as an extra alarm on top of (a) or (b), not
   as the lock itself.
2. **What a stranger may send.**  A request with no note at all, or a
   note too, saved as a message from an unknown sender?

## Suggested Implementation Steps

1. Settle the open questions.
2. Write the steps then; this issue is a design record until it is
   settled.

## Status

**Built 2026-11-06**, branch `claude/715b-public-website`, stacked on
#715a's receiving side.  Waiting for the owner's checks in `q-a-tests.md`.

- **The owner's side.** In public mode the mailbox keeps an X25519 key
  for its website in `.state/website-key`, readable by the owner only.
  It is made on the first start; a file that is there but is not a key
  stops the daemon.  Its six words are logged at every start.  Two plain
  web requests on the mailbox port are answered: `POST /website` gives
  the key and the offer, and `POST /website/piece` gives one MiB at a
  time.  Each request carries the asker's one-off public key, and both
  answers are sealed with the key the two make from them.  Every other
  path, and everything in private mode, is answered exactly as before.
- **The asker's side.** `rmail.lua <config> --website=<host>:<port>
  [--yes]` runs once and exits, beside the asker's own daemon:
  1. It shows the words and the size both ways round, and asks yes or no
     on the terminal.
  2. It remembers the key per address (`.state/website-keys.json`), and
     refuses a changed key loudly.
  3. It checks each piece's line and the whole zip's SHA-256.
  4. It unpacks the zip through #311's checks, and files the site like a
     contact's (#715a).
- `rmail_crypto.c` gains `x25519_public` and `x25519`, tested against
  RFC 7748's vectors.
- Test: `scripts/test-public-website.sh`, with
  `scripts/lib/website-between.lua` playing someone in the middle.

## Decisions (2026-11-06, the owner can overturn any of these)

1. **Open question 1, the way in: (a) and (b) together.**
   - (a) The asker's mailbox remembers the website's key the first time,
     per address, and refuses the site loudly if the key changes, naming
     the words from then and now.
   - (b) Six words from the key are shown on the asker's terminal and in
     the owner's log, for the two people to compare some other way.
   - (c) The timing check is not built. Per the 2026-10-13 assessment
     above, an attacker in the middle can prepare their own sealed file in
     advance, so no extra delay appears. Networks also wobble by more than
     the margin, so the check would mostly raise false alarms.
2. **The owner's "encrypt the file with a random token" is met by the
   agreed key.** Each visit's key comes from a new random key on the
   asker's side and the mailbox's website key, so it is fresh every time.
   Only the asker can open what is sealed with it, and only the
   mailbox's key could have sealed it. A token sent in the clear would be
   read by anyone on the path, and then the words would prove nothing.
3. **Open question 2, what a stranger may send: no note.** A stranger's
   request carries only a key. The inbox is for people the owner chose.
   The public link's notes (#714) are the place where strangers write.
4. **The asker's side is rmail itself, run once, not a Firefox plugin.**
   The asker needs a mailbox anyway, to remember keys and to file the
   site with its information pages. A plugin would be JavaScript, and
   there is no Firefox on the build machine. The two requests are plain
   enough for a plugin to make later.
5. **The site is pulled, not pushed.** A contact's website is pushed to
   their daemon (#715a). A stranger may be behind a router nobody opened,
   so their side fetches it, piece by piece.
6. **The guard: twice the zipped site per address per day.** This leaves
   room for one retry of a whole download, and a loop stops at once. It is
   counted in memory, so it is forgotten at a restart. The log says once
   when an address reaches it.
7. **The zip is made on the first ask after the folder changes**, and is
   then kept in the pending folder while the daemon runs. Packing blocks
   the daemon for as long as it takes, so a site of many GB stalls it
   once per version. That is left for the owner's checks.
8. **Filed as `websites/<name>-at-<host>-<port>/`.** The name comes from
   the sealed offer, and the address keeps it apart from a contact's site
   of the same name.
9. **Public mode with no `website` stops the daemon**, as other config
   mistakes do. A `libs/rmail_crypto.so` built before this change also
   stops it, with the command that rebuilds it.
10. **Contacts still ask as in #715a** in public mode, and a listen-only
    contact is still offered nothing that way. It can fetch like anyone
    else.

