# #715a — A contact asks for the website and is offered the whole of it

Sub-issue of #715.

## Current Behavior

*Built in part, 2026-11-05 (see Status):* the config keys, the request,
the offer and the guard.  Not built: the receiving side (one site per
contact) and the information pages.

Built 2026-10-13 and relied on here: an arriving message never writes over
a file already in the inbox; a taken name moves the newcomer to the next
free `-2`, `-3` …, with no upper limit (the new-message path of the
receive handler in `rmail.lua`; `scripts/test-inbox-never-overwrites.sh`).

## Intended Behavior

### The config keys

In the mailbox's config file:

```
# a folder to publish as this mailbox's website; contacts who ask get it
website = site
# private: only contacts may ask.  public: anyone may (see #715b)
website_access = private
```

A relative path is taken from the folder holding the config file, as hook
paths are.  Unset or empty means no website.  A `website` that names
something that is not a folder is an error at start-up, not a quiet
fallback (house rule: errors over fallbacks).  Until #715b is built,
`website_access = public` is also an error at start-up.

### How a contact asks

The contact writes an outbox file named `website`, addressed to the owner:

```
to: gabrilend

Hi! Found your address on the forum.
```

On the owner's side, the receiving daemon recognises the subject
`website`:

1. It **does not keep a file named `website`** in the inbox; the request
   is used up on arrival.
2. If the body has any text, the text is saved as an ordinary inbox
   message whose filename is the **receiving machine's date and time, to
   the millisecond** (for example `2026-10-13-14-03-27-512`).  It never
   overwrites anything (see Current Behavior).
3. It answers by writing an outbox message to the requester, which the
   normal sending machinery delivers:

```
to: alice
attach: <the website folder>

<the offer text below>
```

A folder attachment is already zipped before it goes
(`compress_attachment`), and the requester's side already writes a
consent form for it (#301).

### The offer text

Says the size two ways, from two directions, as the owner asked
("explained two times twice from each a different direction"):

> This is gabrilend's website, 15 GB in all, zipped.
> Say yes on the consent form and all of it arrives, to read whenever
> you like, even offline.
>
> Said the other way round: saying no costs you nothing and you can ask
> again later; saying yes costs 15 GB of disk, but then it is yours and
> works without gabrilend's computer being on.

### Guard against asking over and over

A request is a few bytes; the answer can be gigabytes.  Without a guard,
anyone allowed to ask can make the owner's machine send the whole site
again and again: one line in a loop on their side, hours of upload on
the owner's.  The owner (2026-10-13): "how many times will we continue
sending attachments, messages, or websites to users if they just... keep
requesting the same thing over and over again? We need to add some sort
of guard to that."

Proposed rule, per contact:

- **At most one offer waiting.**  While an offer of the website to a
  contact waits for its consent answer, or its transfer is running, a new
  request from that contact makes no new offer.  Its note (if any) is
  still saved.
- **Nothing new, nothing sent.**  The daemon keeps a fingerprint of the
  folder (a SHA-256 over every file's path, size and contents, in sorted
  order) beside the contact's record of what it last received.  A request
  when the contact already accepted the same fingerprint makes no new
  offer.
- **Every request that makes no offer is one log line**, naming the
  contact and the reason, so the owner can see someone asking repeatedly.

Ordinary messages and attachments are not affected: they are only sent
when the owner writes them, so a contact cannot make the owner send them
again.  The website is the first thing a contact can make the owner's
daemon send by itself.

### One website per contact, on the receiving side

The owner (2026-10-13): "it's one website per contact. So they wouldn't
request if they didn't want to overwrite. Maybe we can move the old
version to RAM?"  When a website from a contact arrives, it replaces the
previous one from the same contact.  The previous one is moved into the
mailbox's RAM folder (`/tmp/rmail-progress/`, or the `/dev/shm` tier if
`/tmp` is on disk on this host) rather than deleted, so it can be looked
at until the machine restarts.

### Large files inside the site

A `.zip`, `.mp4` or other non-page file in the folder is never opened just
because a page linked to it.  The site's zip carries, beside each such
file, an information page that a link to it is pointed at instead:

- what we know about the file: name, size, type (from its extension),
  date modified, and a SHA-256 checksum the reader can compare;
- an **open this file** button;
- a few boxes styled like web ads, some reading "CLICK ME, I'M AN AD",
  each linking to a Wikipedia article: Malvertising, Drive-by download,
  Clickbait, Phishing, Trojan horse (computing), Dark pattern, Attention
  economy, Checksum.  Generic ad-shaped boxes, without Google's name or
  logo.  Approved by the owner 2026-10-13 ("sounds good").

## Open questions

1. **Asking again after accepting.**  If a contact has the current
   version and asks again (they lost it, say), should they get it?  The
   rule above says no.  The owner could send it by hand.
2. **Rewriting links in the owner's pages.**  Pointing a page's link at
   the information page means changing the owner's HTML inside the zip.
   Or the information pages could sit beside the files, with the owner
   linking to them.  Which?

## Suggested Implementation Steps

1. Read and check `website` and `website_access` at start-up.
2. In the receive handler's new-message path, before a message is
   filed: recognise the subject `website` from a contact; save any note
   under the millisecond date name; apply the guard; write the answering
   outbox file.
3. Keep, per contact, the fingerprint offered and the fingerprint
   accepted, in the saved state.
4. On the receiving side, recognise an arriving website and move the
   previous one from the same contact into RAM.
5. Build the information pages into the zip.
6. Test with two throwaway mailboxes in RAM: the requester gets a consent
   form, accepts, and receives the zip; a second request while the offer
   waits makes no second offer; a request after accepting the same
   version makes none; changing one file in the site makes a new offer;
   a note sent with the request is saved under a date name.

## Status

Open: the sending side is built (2026-11-05, branch
`claude/715a-website-on-request`, stacked on #714's branch only to keep
the two changes to `rmail.lua` from colliding; it needs nothing of #714).

Built:
- `website` and `website_access` read and checked at start-up: a website
  that is not a folder, `website_access = public`, and any value but
  `private`/`public` each stop the daemon with the reason.
- A message called `website` (any case) from a contact, when a website is
  configured: no file of that name is kept; any text is saved under the
  receiving time to the millisecond; the daemon writes
  `website-for-<contact>` (`to:`, `attach: <folder>`, the offer text) to
  its outbox, and the usual machinery sends the consent form and the zip.
- The guard, per contact, in `.state/website.json`: no offer while one
  waits or travels; none when they already received this version; every
  refused request one log line with its reason.
- Test: `scripts/test-website-request.sh`.

Not built: steps 4 and 5 below (the receiving side, the information
pages).

## Decisions (2026-11-05)

Made while building, to be overturned by the owner's word:

- **Open question 1, asking again after accepting: no.**  The owner asked
  for a guard against repeated requests (2026-10-13), and a contact who
  lost the site is one the owner can answer by hand, with an outbox file
  attaching the folder.  A changed site is a new version and is offered.
- **Open question 2, the information pages: beside the files, the owner's
  pages untouched.**  The zip stays the owner's site byte for byte, and
  rewriting links means parsing HTML, which breaks on hand-written pages.
  The owner links to `<file>.info.html` where they want the warning.  Not
  built in this slice.
- **The fingerprint is over each file's path, size and modification time,
  not its contents.**  Hashing a 15 GB site at every request would let a
  contact make this machine read 15 GB for a few bytes, which is what the
  guard is for.  An edit changes the time.
- **The offer is `website-for-<contact>`**, and a new offer takes the next
  free `-2`, `-3` …: the old offer file is deleted (so the contact is told
  to delete the old message) and the new one has a name the next pass has
  never seen, so it is sent rather than taken for the old file.
- **A request with no text keeps nothing** and is recorded as a message
  already deleted, so the next pass tells the sender and their `website`
  file leaves their outbox; one with a note stays on their side until the
  owner deletes the note, as any message does.
- **The answer to a request is always 200**, offer or not, so a contact
  cannot learn from it whether the guard stopped them.
- **With no website configured, `website` is an ordinary message**, so
  the owner still sees that someone asked.
- **A listen-only contact is never offered it** (#420: never sent
  anything); its note is kept.
- **The note is saved as it came**: the receive hooks, which are for mail,
  do not run on it.
- No datapath document: `docs/` has none to follow yet; the feature is
  described in `docs/.templates/attachments.md` and the README.
