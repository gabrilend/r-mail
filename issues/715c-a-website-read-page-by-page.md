# #715c — A website read page by page

Sub-issue of #715.  Needs #715a.  **Deferred by the owner, 2026-10-13**:
"this is stretch behavior, let's push the incremental website caching
download operation setting for later".  Built anyway on 2026-11-06, as a
draft for the owner to take or leave (see Status).

## Current Behavior

A website is sent whole to a contact (#715a) or to a stranger who asks
(#715b).  With `--browse` (below), a public website can also be read page
by page.

## Intended Behavior

Instead of downloading the whole zipped site, the reader can read it page
by page, the way a web site is read.  Each page they open is fetched from
the owner's mailbox and kept on their computer, so opening it again costs
nothing.  The owner (2026-10-13): "if they browse to another part of the
page, it should download to their computer. Cached. Or, they should
download the whole site all at once."  Their earlier words for the
reader's choice: "download all website attachments? cache web pages on
server?"

The offer from #715a then names both choices, each explained from two
directions: everything now (costs the whole size, works offline) or page
by page (costs only what is opened, needs the owner's computer on).

Proposed shape, not yet agreed: the reader's own daemon serves the site
to their browser on their own computer only (`localhost`), fetching each
page from the owner's daemon over sealed rmail.  Plain http then never
leaves the reader's machine.  The owner also mentioned an rmail Firefox
plugin, which might do this part instead.

Path safety is the critical guard for any per-page fetch: refuse `..`,
absolute paths and encoded slashes; resolve symlinks and check that the
result stays inside the website folder.

## Open questions

1. The local daemon, or the Firefox plugin?

## Suggested Implementation Steps

1. Settle the open question when this is picked up again.
2. Build the per-page fetch with its path guard and tests that try each
   refused path.
3. Keep fetched pages on disk per contact; test that a second open does
   not ask the owner.

## Status

**Built 2026-11-06**, branch `claude/715c-website-page-by-page`, stacked
on #715b.  This was built although the owner deferred it on 2026-10-13,
because the work list for 2026-11-06 named it; it is a draft, and leaving
it unmerged costs nothing.  Waiting for the owner's checks in
`q-a-tests.md`.

- **The owner's side.** In public mode one more web request is answered
  on the mailbox port: `POST /website/page {key, path, from}` gives up to
  one MiB of one file, sealed with the key of #715b, behind a line naming
  the offset, the file's size, the site's version and the file.  A folder
  means its `index.html`.  `POST /website` with `browse: true` gives an
  offer with no zip made.
- **The path guard**, on both sides: no `..`, no part that starts with a
  dot (dotfiles are not published), no absolute path, no empty part, no
  backslash, no control byte, no `%`.  The reader refuses an encoded
  slash or backslash before it decodes the browser's `%` escapes once.
  The owner then follows every link (`realpath`) and refuses anything
  that lands outside the website folder.  A refusal is logged.
- **The reader's side.** `rmail.lua <config> --website=<host>:<port>
  --browse[=PORT]` meets the owner as #715b does (the words, the
  remembered key, a yes-or-no question naming the cost both ways round),
  then serves the site at `http://127.0.0.1:PORT/` (8715 by default) to
  this computer's own browser, until stopped.  Each file is fetched once
  and kept at `attachments/websites/<owner>-at-<host>-<port>/`, the same
  place a whole fetch fills; `.rmail-website.json` there says which
  version.  A newer version moves the kept copy to RAM, as #715a does.
- Test: `scripts/test-website-browse.sh`.

## Decisions (2026-11-06, the owner can overturn any of these)

1. **Built, though deferred.**  The owner's 2026-10-13 words put this
   later; the work list for 2026-11-06 asked for it.  It is a separate
   draft on top of #715b, so the owner can leave it for later exactly as
   they said, at no cost to 715a or 715b.
2. **The open question, the local daemon or the Firefox plugin: the
   local rmail program.**  Firefox is not on this machine to build or test
   a plugin, a plugin is JavaScript (the project prefers none), and the
   owner's own proposal shape was the reader's daemon on `localhost`.  A
   plugin can still be built later on top of the same `/website/page`.
3. **A separate run, not the daemon.**  `--browse` runs in the
   foreground beside the reader's daemon, as #715b's `--website` does, and
   listens on 127.0.0.1 only.  The daemon's main loop serves contacts; a
   page fetch that waited on a slow owner would hold it up.
4. **Public websites only.**  A contact's website (private mode) is still
   sent whole.  A contact's requests ride the outbox and its sync timer
   (30 seconds or more), far too slow for one click; the page route is a
   plain sealed web request, which in private mode the mailbox does not
   answer.  A contact can still browse a public website.
5. **The offer names both ways.**  #715b's fetch now ends its cost text
   with "To read it page by page instead, add --browse", and `--browse`
   says the other way round: without it, all of it arrives at once and
   works offline.  The consent is asked once per run.
6. **One place for both.**  Pages read one at a time are kept where a
   whole fetch puts the site.  A whole fetch writes the version record
   too, so browsing a site fetched whole asks the owner for nothing.
7. **The guard counts pages.**  Pages count against #715b's allowance per
   address, twice the site a day, measured unpacked for pages (no zip is
   made for them).
8. **Information pages are made when first asked for.**  #715a writes
   `<file>.info.html` beside each file that is not a page part when a site
   arrives.  Here one is made the first time the browser asks for it.  The
   page shows the file's checksum, so the file is fetched to make it;
   that costs the download, but the file is still not opened.
9. **Only this computer's own name.**  The reader's server answers only
   requests whose `Host` is `127.0.0.1:PORT` or `localhost:PORT`, so a page
   elsewhere that renames itself to 127.0.0.1 cannot read the kept copy
   through the browser.
10. **A folder's page without its slash** is sent to the slash (301), so
    the page's own relative links work.
11. **A file whose name holds `%`** cannot be read page by page: the
    reader decodes once, and a `%` left over is refused as an escape
    inside an escape.  A whole fetch still carries it.
