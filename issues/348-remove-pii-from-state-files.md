# Remove PII from state files

## Overview

`.state/` currently caches substantial personally identifiable information
that duplicates what's already in `~/mail/contacts` and the message files
themselves. Ideally, deleting a message file (and the contact if desired)
would leave no residue of who the user talked to or what was said. Today,
state files retain subjects, contact names, tokens, paths, and content
fingerprints independent of the source-of-truth files.

## Current PII in state

**inbox.json** — keyed by filename (= message subject):
- key itself: subject (content)
- `from`: contact name
- `message_id`: UUID (not identifying)
- `attachments[name]`: attachment filenames, saved paths, ids

**outbox.json** — keyed by filename (= subject):
- key itself: subject
- `body_checksum`: SHA-256 of the message body (content fingerprint)
- `recipients[name]`: contact name as key
- `recipients[name].token`: shared secret duplicated from contacts
- `recipients[name].message_id`: UUID

**chunks-outgoing.json** — attachment transfers in flight:
- `outbox_file`: subject
- `to`: recipient name
- `filename`: attachment filename
- `original_path`: full path on user's filesystem
- `compressed_path`: temp path
- `total_checksum`: content fingerprint
- `expected_size`

**consent-pending.json / consent-responses.json** — attachment consent:
- similar metadata, including filenames, sender/recipient names, message_ids

**nat_security_warned.json**, **pending-address.json** — network metadata
that could link to specific contacts via IP/port.

## Proposal

Re-key state by `message_id` instead of filename. All persistent lookups
use the UUID; filenames are discovered from the filesystem when needed.

For tokens in `outbox.json`: stop duplicating. Read from `contacts` at send
time. Trade-off: if the contacts file is temporarily unreadable, in-flight
sends will fail rather than completing from the cached token. That's
acceptable — tokens shouldn't outlive the contact.

For `chunks-outgoing.json`: drop `original_path` once the first chunk is
assembled. Keep only the `zip_id` needed to continue an in-flight transfer.

For attachment filenames in inbox.json: derivable from the file on disk,
don't cache.

## Desired post-refactor state

After the refactor, `.state/` should contain roughly:

- inbox.json: `{message_id: {}}` — presence indicates "we have it", everything
  else derived from inbox/ contents and contacts file
- outbox.json: `{message_id: {body_checksum, recipients: {message_id_per_recipient}}}`
  — keyed by our message id, recipients tracked by their ids, no names or tokens
- chunks-outgoing.json: transfer resume state only (zip_id, chunks sent),
  no paths or names

## Rationale

Deleting `inbox/meeting-with-legal` should erase all evidence of the meeting.
Today it leaves `inbox.json["meeting-with-legal"] = {from: "alice", ...}`
until the next sync cycle notices and sends a delete notification. Worse,
the body_checksum in outbox.json persists even after the file is deleted
if the sender hasn't synced recently.

This matters for: shared machines, forensic acquisition, backup contents,
and anyone auditing `.state/` for what rmail retains.

## Trade-offs

- Performance: filename-keyed state is O(1) on delete; message_id-keyed
  requires scanning or a secondary message_id → filename index. For realistic
  mailbox sizes (hundreds to low thousands of messages) this is negligible.
- Durability: dropping the token cache means contact-file unavailability
  breaks in-flight sends. Acceptable.
- Code churn: every state access in rmail.lua changes. Touches every handler
  that reads/writes inbox.json, outbox.json, or chunks-outgoing.json.

## Open questions

- `from` in inbox.json: strictly derivable from which contact's token
  decrypted the message at receive time. We could drop it and re-derive on
  demand, but that requires trying each contact's key against the stored
  ciphertext — expensive. Alternative: encrypt the `from` field at rest
  with a key derived from the message_id + a local master key.
- The filesystem itself still carries the subject (as the filename). Full
  PII removal would require either renaming on-disk files to their UUIDs
  (bad UX) or accepting that the filesystem leaks subjects.

## Related

- Issue 306 introduced `body_checksum` for living message detection — any
  refactor must preserve that check without leaking content fingerprints
  unnecessarily.

## Status

Not started. Scope is large enough that it should be split into per-file
migrations, starting with the simplest (nat/address state) and working up
to the big ones (inbox.json, outbox.json).
