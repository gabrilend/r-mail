# #715 — The mailbox serves its owner's website

## Current Behavior

Nothing is built.  There is no config key naming a website and no way to
ask for one.  The mailbox's port answers a browser's `GET` (any path)
with the plaintext health answer `{"ok":true}` (#106), and this design
leaves that alone.

## Intended Behavior

Each mailbox owner can publish a small website about themselves: who they
are, how to reach them, how to become a contact.  It is one folder on
disk, named by one config key.  Someone who asks gets **the whole folder,
zipped, as an attachment offer**: the consent form tells them its size and
they say yes or no (#301).  By default only the owner's contacts may ask;
a config switch opens it to anyone.

The owner's words (2026-10-12): "users will host websites on their r-mail
that tells people how to connect and who they are and such."  And: "There
should be just one config option for just one directory that we use as
the thing that we're sending (zipped before it goes)."  On 2026-10-13:
"if we get that HTTP request, then we send the whole website, and they
confirm it's size as an attachment consent form."

### Sub-issues

| ID | Name | Dependencies | Description |
|---|---|---|---|
| 715a | a-contact-asks-for-the-website | None | the config keys, the `website` request, the offer of the whole zipped folder, the guard against repeated requests, one site per contact on the receiving side, the information page for large files |
| 715b | anyone-may-ask-for-a-public-website | 715a | `website_access = public`: a stranger's request, and how the answer can be trusted over a channel nobody has a key for yet |
| 715c | a-website-read-page-by-page | 715a | instead of the whole zip, each page the reader opens is fetched and kept on their computer.  Deferred by the owner: "this is stretch behavior, let's push the incremental website caching download operation setting for later" |

Execution order: `715a (foundation) → 715b (needs 715a) → 715c (needs
715a, parallel with 715b)`.

## Suggested Implementation Steps

1. Build 715a; this parent is done when all three are.
2. Document the keys in the README's config section and in
   `docs/attachments.md`; add a datapath document for the feature; add a
   change-log line to the README for each sub-issue completed.

## Related

- #714 — the per-message public link, on its own port, for people
  without rmail.  This issue is the mailbox-wide site, for rmail users.
- #301, #312 — consent before any byte; a declined offer is not offered
  again.
- #420 — listen-only contacts.

## Origin

Requested 2026-10-12: "can you add an endpoint that returns my website
anytime someone sends that HTTP request? We should be able to point to a
directory in our config file and say 'website to return' but if it's an
attachment, then we send an attachment request to the rmail message that
requested it 'do you want to download this zip? details here:'"

Dropped on 2026-10-13: a plain-http site on the mailbox port (and with it,
moving the health answer to `/health`).  The owner: "this is why it's
encrypted to only my peers."

## Status

Open.  715a has two open questions; 715b is still being designed; 715c is
deferred.
