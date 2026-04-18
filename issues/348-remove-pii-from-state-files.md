# Remove PII from state files

## Status: reversed

Steps 1–5 landed in commits between 2026-03 and 2026-04; step 6 was
implemented in a single session on 2026-04-17 and then unwound later
in the same session without ever being committed, as part of this
reversal.  After reconsidering with fresh eyes, the entire effort is
being **reversed** and the remaining work cancelled.  The short version: the threat model
is thin, the inspectability cost is real, and "users should be able to
`cat` their state and understand what's happening" outweighs the
marginal defense that name-hashing provided.

The sections below are ordered from "decision + what to do about it"
down to "original plan, preserved for historical reference."

## Why we reversed course

### 1. The threat model was always thin

Every step of this work was in service of one scenario: someone reads
`.state/` but **not** `~/mail/`.  In practice that means a
misconfigured backup, a split forensic acquisition, or an rsync that
grabbed the wrong subtree.

In every realistic case — stolen laptop, shared machine, full-home
backup, snapshot of the mailbox — the attacker gets `contacts` and
`inbox/` too.  Contact names are then visible in four other places on
the same disk:

- `~/mail/contacts` (one row per contact, token in plaintext)
- `inbox/<filename>` (contents mention senders routinely; reply/
  forward quoting; application-level `from:` headers)
- `outbox/<filename>` (`to:` lines are contact names)
- `attachments/<filename>` (filenames chosen by senders)

Hashing names in `.state/` while leaving them in all four of those
other files is an own-goal: one less copy of "alice" among five.

The hashing is also unkeyed `SHA-256("rmail:contact:" || name)`.
Anyone with `contacts` reverses every state hash in O(contacts).
It's a speed bump against a misconfigured backup, not a defense.

### 2. The inspectability cost is real

rmail's pitch is "your data, on your disk, in files you can read."
Post-#348, `cat .state/inbox.json` returned 64-character hex blobs
where a contact name used to be.  Debugging became a mental
hash↔name translation or a shell helper.  For a project whose
self-inspection properties are a deliberate design goal, that's a
direct regression against the thing the project is supposed to be.

### 3. The "re-key by message_id" work would have made it worse

The remaining proposed work — making `inbox.json` / `outbox.json`
maps keyed by UUIDs instead of filenames — would have turned state
files into opaque join tables against the filesystem.  Maximum PII
win, maximum debuggability loss.  Not worth doing.

### 4. Content-addressed `message_id`s don't work cleanly anyway

The original proposal suggested `message_id = SHA-256(sender ||
body)`.  That works for attachments (immutable zip; the integrity
checksum *is* the id) but conflicts with #306 living messages:
editing a body changes the hash, which breaks the "same message,
updated" identity the update flow depends on.  You can paper over
it by sending `{old_id, new_id}` on every update and rekeying on
both sides, but that reintroduces the idempotent-retry and
partial-rekey edge cases a UUID avoids for free.

The "self-validating" property also turned out weaker than it
looked: AES-GCM already provides integrity on the wire, and a
content-hash id would have to live *inside* the encrypted payload
to be useful — which is circular (if the payload doesn't decrypt,
the hash check never runs).

### 5. Tokens in state: the one real concern, solved differently

The *one* genuine PII concern this work identified was that pre-#348
`outbox.json` duplicated each contact's shared-secret token into
state.  Tokens are real secrets, not labels, and duplicating them
mattered.

But the token-in-state only served one purpose: **contact-rename
detection**.  Every *send/auth* path already reads
`contacts[name].token` fresh at send time — the state copy was a
fingerprint used to auto-migrate state entries when a user renamed
`alice` → `alice-smith` in contacts.

Drop rename detection, and the token has no reason to be in state at
all.  So: we drop rename detection, and with it the entire motivation
for step 5's `token_hash`.  Renames become a user-serviced
operation (see "Recovery path" below), which is fine on fully
plaintext state because it's a few lines of `sed`.

## Decision

- **Revert steps 1, 2, 3, 4, 5, 6.**
- **Delete the rename-detection block** in `sync_outbox`
  (`contact_by_token_hash`, `contact_by_token_plain`, the renames
  loop, the associated state-mutation code).
- **Do not** pursue the remaining proposed work (re-key by
  `message_id`, strip `chunks-outgoing.json` filesystem paths,
  hash/derive `consent-pending.json` fields).  Close this issue.

State files become what they should have been all along: **plaintext
mirrors of the source-of-truth files (`contacts`, `inbox/`,
`outbox/`), inspectable with `cat` and fixable with `sed`.**

## Revert plan

For each step, what to undo and what to preserve:

### Step 1 (7d11b30) — `nat_security_warned.json`, `pending-address.json`

- Go back to keying by plaintext contact name.
- Add a one-shot "reverse migrator" on load that detects 64-hex
  keys, attempts to resolve them against the current contacts via
  `SHA-256("rmail:contact:" || name)`, and replaces resolved keys
  with the plaintext name.  Unresolvable keys get dropped (orphans
  from deleted contacts).
- Delete `migrate_hashed_state()` after migration: it's the only
  caller of itself once the reverse path is in place; a future
  idle fn.

### Step 2 (bundled into 07681da) — `chunks-outgoing.json` `.compressed_path`

- Put `.compressed_path` back onto each transfer entry.
- Drop `zip_id` and the `zip_path_for(zip_id)` helper.  Every
  current use is `zip_path_for(t.zip_id)` — replace with
  `t.compressed_path` directly.  `release_zip` compares paths
  instead of ids; nothing on the wire changes.

### Step 3 (ecb03fc) — `chunks-outgoing.json` `.to` hashing

- Remove the hash-on-save / resolve-on-load in
  `save_chunks_outgoing` / `load_chunks_outgoing`.
- The wrappers themselves can stay as named passthroughs (tidy)
  or collapse back into direct `load_state` / `save_state` calls
  (less code).  Either is fine; preference: inline if the wrapper
  has no remaining logic, keep if there's any boundary work.

### Step 4 (b0be14f) — `consent-pending.json` `.from`, `consent-responses.json` `.to`

- Same treatment as step 3: drop the hashing, collapse or keep
  the wrappers as preference dictates.

### Step 5 (3cd723c) — `outbox.json` tokens

- **Do not** put plaintext `.token` back into state.  Tokens stay
  in `contacts` only.
- **Do not** keep `.token_hash` either — it existed only for
  rename detection, which is being deleted.
- `save_outbox_state` no longer needs to strip `.token` or hash
  anything; it can be deleted (collapse to `save_state("outbox.json", ...)`).

### Step 6 — `inbox.json` `.from` hashing

Step 6 never landed in a commit; it was implemented in-session and
unwound before the revert series started.  No code changes needed for
this step — it simply never enters the git history.  The `#348 begin
reversal` commit that lands this document replaces the in-tree step-6
code with the pre-step-6 call sites.

### Rename-detection deletion

- Delete the rename-detection code block in `sync_outbox`
  (`contact_by_token_hash`, `contact_by_token_plain`, the renames
  loop that mutates `fmeta.recipients`).
- Add a short comment where the block used to be pointing at the
  recovery path below.
- Remove any Android-side code that consumes `.token`/`.token_hash`
  fields from state (none expected, but audit).

### Shared-helper cleanup

- `hash_contact_name`, `migrate_hashed_state`, `_is_hash` become
  unused — delete.
- `hex_sha256` stays: it's still used by `canonical_contacts_hash`
  (protocol-level contacts-file digest, not state-file PII).

## Recovery path for contact renames

Without auto-detection, renaming a contact while messages are
in-flight is a user-serviced operation.  Symptoms the user will see:

- Daemon logs `unknown contact '<old-name>' in <file>` on each
  sync cycle.
- Body edits to that message no longer propagate to the renamed
  recipient.
- If the renamed recipient deletes the message, the sender returns
  404 to their delete-notify (the delete is lost; state orphans on
  sender's side).
- If the sender changes `to: <old-name>` to `to: <new-name>` in
  the outbox file without also fixing state, the state's
  `<old-name>` entry is seen as a removed recipient (silently
  dropped) and `<new-name>` as a new recipient (full re-delivery
  — the receiver gets the message twice).

Recovery is three steps:

1. Rename in `~/mail/contacts` (the source of truth).
2. Update any `to: <old-name>` lines in affected outbox files to
   `to: <new-name>`.
3. `sed -i 's/"<old-name>"/"<new-name>"/g' .state/*.json` — covers
   `outbox.json`, `chunks-outgoing.json`, `consent-pending.json`,
   `consent-responses.json`.

This should be documented in the user-facing docs (README or a
"troubleshooting" section) once the revert lands.

### Why not keep rename detection with in-memory diffing?

We considered: have the daemon hold the previous contacts snapshot
in memory, and when the contacts-file inotify watcher fires, diff
old vs new.  Names that disappear alongside names that appear with
the same token would be auto-migrated across state files, with
nothing written to `.state/` about tokens.

Rejected because:
- It only works when the daemon is running at the moment of the
  rename.  A user who stops the daemon, edits contacts, restarts,
  gets no benefit — they're on the manual path anyway.
- The manual path is `sed`, which is ~10 seconds for a once-a-year
  event on fully plaintext state.
- Adding ~50 lines of code for a partial win is worse than the
  consistent story of "state is plaintext, renames are
  user-serviced."

Noted for the record in case the tradeoff changes.

---

## Historical record: original plan (superseded)

Everything below is preserved for context.  The conclusions reached
here no longer apply; see the "Why we reversed course" and
"Decision" sections above.

### Overview (original)

`.state/` currently caches substantial personally identifiable
information that duplicates what's already in `~/mail/contacts` and
the message files themselves.  Ideally, deleting a message file
(and the contact if desired) would leave no residue of who the
user talked to or what was said.  Today, state files retain
subjects, contact names, tokens, paths, and content fingerprints
independent of the source-of-truth files.

### Current PII in state (inventory, still accurate)

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

**consent-pending.json / consent-responses.json** — attachment
consent: similar metadata, including filenames, sender/recipient
names, message_ids.

**nat_security_warned.json**, **pending-address.json** — network
metadata that could link to specific contacts via IP/port.

### Original proposal (superseded)

Re-key state by `message_id` instead of filename.  All persistent
lookups use the id; filenames are discovered from the filesystem
when needed.  Content-addressed ids via
`SHA-256(sender || content)` were considered and rejected (see
"Why we reversed course" / point 4).

The intended post-refactor shape was:
- `inbox.json`: `{message_id: {}}` — presence indicates "we have
  it"; everything else derived from `inbox/` contents and contacts.
- `outbox.json`: `{message_id: {body_checksum,
  recipients: {message_id_per_recipient}}}` — keyed by our message
  id, recipients tracked by ids, no names or tokens.
- `chunks-outgoing.json`: transfer resume state only (`zip_id`,
  chunks sent), no paths or names.

### Completed steps (to be reverted)

- **step 1** (7d11b30) — `nat_security_warned.json` and
  `pending-address.json` now key by `SHA-256("rmail:contact:" ||
  name)` rather than plaintext contact names.  `migrate_hashed_state()`
  one-shot upgrades legacy files on load.  Also dropped the dead
  per-contact timestamp value in `nat_security_warned.json`.
- **step 2** (bundled into 07681da) — `chunks-outgoing.json` dropped
  the `compressed_path` field; new `zip_path_for(zip_id)` helper
  derives it from the stored `zip_id` instead.
- **step 3** (ecb03fc) — `chunks-outgoing.json` hashes the `.to`
  (recipient contact) field.  New `load_chunks_outgoing()` /
  `save_chunks_outgoing()` wrappers translate at the disk boundary.
- **step 4** (b0be14f) — `consent-pending.json` hashes the `.from`
  field; `consent-responses.json` hashes the `.to` field.
- **step 5** (3cd723c) — `outbox.json` no longer stores plaintext
  shared-secret tokens in `recipients[name].token`.  Replaced with
  `token_hash = hex_sha256(token)`; rename-detection code hashes
  contacts' tokens into the same space so it still works.
- **step 6** (implemented in-session 2026-04-17, never committed,
  unwound before the revert series) — `inbox.json` hashes the
  `.from` (sender contact name) field.  New `load_inbox_state()` /
  `save_inbox_state()` wrappers replace the 12
  `load_state("inbox.json")` and 7 `save_state("inbox.json", …)`
  call sites.  Recorded here for completeness since the plan
  document committed to doing it; the code never entered main.

Shared infrastructure landed during step 5: `hex_sha256(data)`
helper consolidates the three sites that previously had
hand-rolled bytes→hex loops.  This helper stays after the revert
(it's used by `canonical_contacts_hash`, not just the PII work).

### Related

- Issue #306 introduced `body_checksum` for living-message
  detection.  The original #348 proposal wanted to collapse
  `body_checksum` into a content-hashed `message_id`; after the
  reversal, `body_checksum` stays a separate field (see point 4
  above).
- Issue #346 landed the attachment-consent cleanup.  Receiver's
  `consent-pending.json` is already keyed by `att_id` and is
  cleared the moment the transfer ends, so the consent-pending
  PII window was already narrow.  Nothing in the revert changes
  that.
