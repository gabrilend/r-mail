# #715c — A website read page by page

Sub-issue of #715.  Needs #715a.  **Deferred by the owner, 2026-10-13**:
"this is stretch behavior, let's push the incremental website caching
download operation setting for later".

## Current Behavior

Nothing is built.  A website is only ever sent whole (#715a).

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
