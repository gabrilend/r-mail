# #715b — Anyone may ask for a public website

Sub-issue of #715.  Needs #715a.

## Current Behavior

Nothing is built, and the design is not settled.  Only contacts may ask
for a website (#715a).

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
