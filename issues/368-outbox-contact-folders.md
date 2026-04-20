# #368 — Contact-named outbox folders: drop a file in, it sends to that contact

## Problem

The current outbox workflow puts the recipient inside the file, as
`to: <name>` at the top of the header block. That's fine for
one-off messages, especially multi-recipient ones. But for a user
whose outbox workflow is "I'm writing to alice a lot today, I'd
like to just drop files into alice's pile and have them get sent,"
the `to:` line is friction.

Right now, if a user creates `~/mail/outbox/alice/` and drops a
file into it, the daemon:

1. Logs "ignoring directory /home/…/outbox/alice — rmail sends
   regular files. To send the directory as an attachment, create a
   new outbox message with a line like: attach: /home/…/outbox/alice"
   (`rmail.lua:305`).
2. Never looks at the file inside.

That's the right default when the directory name doesn't match a
contact. When it *does* match a contact, the user almost certainly
meant "send these to alice."

## Proposal

If `~/mail/outbox/<NAME>/` exists and `<NAME>` matches an entry in
`contacts`, the daemon treats every regular file directly inside
that directory as an outbox message with `<NAME>` as the **first
recipient**. No `to:` line required in the file itself — the
directory name *is* the first `to:` line, logically.

```
~/mail/outbox/
    alice/              ← directory named after contact "alice"
        quick-note      ← sent to alice; body = file contents, subject = "quick-note"
        birthday-plan   ← sent to alice
    hello-world         ← regular outbox file with `to:` lines as usual
```

Files in a contact folder support everything regular outbox files
do — body edits (#306), attachments, glob expansion (#362),
missing-file markers (#363), delete propagation. The only
difference is where the first recipient comes from.

## Design details

### Directory name matching

At the top of `sync_outbox`, after loading contacts, build a set of
contact names. For each subdirectory directly inside `OUTBOX`:

- Name matches a contact → treat as a **contact folder**. Enumerate
  its regular files and treat each as a message whose implicit
  first recipient is the directory's contact.
- Name does not match a contact → existing "ignoring directory"
  warning fires (once per session, same as today).

Matching is exact and case-sensitive, same as how `to:` lines
resolve.

### Extra `to:` lines are additional recipients, not conflicts

A file inside a contact folder can still have its own `to:` lines.
The directory gives the first recipient; any `to:` lines inside
the file name **additional** recipients. Every recipient — the
folder-implicit one plus every explicit one — receives the
message through the normal delivery pipeline.

Example: `outbox/alice/birthday-plan` containing

```
to: bob
to: carol

hey everyone, birthday's on friday at 7
```

sends to alice, bob, and carol. No warning, no `// AMBIGUOUS`
marker — this is just how multi-recipient works when one of the
recipients is given by location.

If the file has a `to: <same contact as the folder>` line (e.g.
`to: alice` inside `outbox/alice/`), that's a no-op duplicate —
silently deduplicate, no warning.

### Do not edit the file to add a synthetic `to:` line

The implementation must not write a `to:` line into the file on
disk. Two reasons:

1. Users expect rmail to leave their outbox files alone unless
   there's a specific, visible reason (glob expansion from #362,
   missing-file markers from #363 — both under named comment
   conventions). Silently mutating a file to add a header the user
   didn't write is surprising.
2. A file in a contact folder might be binary — a PDF, an image,
   a zip — that the user dropped in as a quick way to send it.
   Prepending text bytes would corrupt it.

Instead, handle the implicit recipient *at parse time*:
`parse_outbox_file` takes an optional `implicit_first_recipient`
argument. If set, the returned `entries` list starts with that
recipient (just like a regular file whose first line is
`to: <implicit_first_recipient>`), then any `to:` lines inside the
file append to it. The file on disk is never written back.

This keeps text and binary files both valid. For binary files, the
parser finds no header lines, so the "body" is the entire file
contents — exactly as the wire protocol would deliver it to a
regular `to: <name>` text message whose body happens to be bytes.
Whether binary-body support actually works end-to-end is a
question for the wire layer; this feature doesn't regress it and
doesn't try to advance it either.

### Files in contact folders must never be dropped for "missing `to:`"

The current parser returns `nil, nil` when it finds no `to:` lines,
and `sync_outbox` logs "skipping: missing 'to:' header." Left
alone, that would fire constantly for empty contact-folder files.

Worse, a later cleanup path treats a file with no current
recipients as "user deleted all to: lines, propagate deletion to
everyone who was there." Applied naively to contact-folder files,
this means any no-`to:` file in `outbox/alice/` would look like a
file the user is "unaddressing" and its state entry would be
cleaned up.

The implicit-recipient rule prevents both. When a file lives in
`outbox/alice/`, the parser treats alice as the first recipient
unconditionally. The file is considered "addressed" for the
lifetime of its existence in the folder.

**Deletion propagates only when the file is physically removed
from the folder** — moved out, deleted, or the folder itself is
deleted. That's the same rule that applies to regular outbox
files today (removal from disk → sync_outbox's deleted-files
cleanup → notify_removal to each recipient). Contact-folder
files slot into that path identically; the only thing the new
code does is ensure they don't get dropped for "no `to:`" while
they're still present.

### State keying: relative path

Outbox state is currently `state[filename]` keyed by basename. Two
files both named `hello` — one in `outbox/` and one in
`outbox/alice/` — would collide. New rule: the state key is the
path relative to `OUTBOX`, using `/` as the separator. So
`outbox/hello` keeps the key `"hello"`, and `outbox/alice/hello`
gets `"alice/hello"`. Sorts nicely in the state file, stays
plaintext and greppable (no hashing per the #348 reversal), and
every existing `state[name]` lookup just starts receiving a
compound key instead of a basename.

### Nested directories mirror structure on the receiver

The folder tree inside a contact folder **is preserved on the
receiver's side**. If the sender has

```
~/mail/outbox/alice/projects/q2-plan.md
```

then on delivery the receiver's daemon writes it as

```
~/mail/inbox/projects/q2-plan.md
```

creating the subdirectory as needed. The same applies recursively:
`outbox/alice/projects/2026/q2-plan.md` → `inbox/projects/2026/q2-plan.md`.

The "subject" that travels over the wire is the path *inside* the
contact folder (the path from the contact folder down to the file,
not including the contact folder itself). From the receiver's
point of view, the subject is simply `projects/q2-plan.md`, and
`sanitize_filename` needs to be replaced (or augmented) with
something path-aware:

- Split the incoming subject on `/`.
- Sanitize each component with the existing filename rules.
- Reject any component equal to `..` or empty.
- Reject absolute subjects (leading `/`).
- Reject components with a leading `.` (no dotfiles via wire).
- Reassemble with `/`, create missing intermediate directories
  when writing the file.

No new wire field needed — the subject string already carries the
filename; it just carries a path now.

State on both sides keys by the full relative path (`state["projects/q2-plan.md"]`
on the receiver; `state["alice/projects/q2-plan.md"]` on the sender).

### Collision with an existing flat inbox entry

A receiver who has `inbox/q2-plan.md` as a flat file and then
receives a new `projects/q2-plan.md` must handle both without
clobbering. The #315 duplicate-filename logic (append a short
`-<message_id_prefix>` when different message_id, merge when same)
already does the right thing when extended to paths — two
different message_ids with the same *relative path* become
`projects/q2-plan.md` and `projects/q2-plan-<short>.md`.

### Rename and deletion

Post-#348 reversal: contact renames are a user-serviced operation.
If `outbox/alice/` contains in-flight messages and the user renames
`alice` → `alice-smith` in `contacts`:

- State entries keyed by `alice/<path>` reference a recipient name
  that no longer exists → same symptom as a `to: alice` line
  pointing at a nonexistent contact: logged as unknown contact,
  skipped.
- Recovery: `mv outbox/alice outbox/alice-smith` and
  `sed -i 's|"alice/|"alice-smith/|g; s/"alice"/"alice-smith"/g' .state/outbox.json`.

Documented alongside the existing rename recovery recipe.

Deleting or moving a file out of a contact folder triggers the
same delete-propagation as deleting a top-level outbox file.
Deleting the contact folder itself triggers deletion for every
file that was in it, recursively.

## Non-goals

- **Per-contact inbox folders** (sender-side mirror of the feature
  — every inbound message from alice lands in `inbox/alice/`).
  Separate feature; worth its own issue if there's demand.
- **Per-contact attachments dir.** Same.
- **Auto-creating the directory** when a contact is added. User
  creates the folder when they want it.
- **Binary-body first-class support on the wire.** Not regressed
  by this feature, not advanced either.

## Implementation sketch

Rough order of changes in `sync_outbox`:

1. Load contacts (already done).
2. Enumerate `OUTBOX` direct children, distinguishing files from
   subdirs. A new helper returns `({top_level_files}, {contact_dirs})`
   where `contact_dirs` is a map `{contact_name -> [file paths inside]}`.
3. For each `(contact, file)` pair in `contact_dirs`, construct a
   "virtual outbox entry" with:
   - state key = `<contact>/<relative path from contact folder>`
   - path on disk = `OUTBOX/<contact>/<relative path>`
   - implicit first recipient = `<contact>`
4. Recurse into subdirectories of contact folders to pick up
   nested paths.
5. Flat files (not in a contact folder) keep their current behavior.
6. Subdirectories whose names don't match a contact still fire the
   once-per-session "ignoring directory" warning.

`parse_outbox_file` gains one optional parameter,
`implicit_first_recipient`; when set, it prepends that recipient to
the returned entries list. All other parser behavior unchanged —
blank/comment tolerance (#363), glob expansion (#362), everything.

Receiver-side changes are confined to `handle_deliver_message`:

- Accept a subject that contains `/`.
- Run it through a path-aware sanitizer (new helper).
- `mkdir -p` the intermediate directories under `INBOX`.
- Key inbox state by the full sanitized relative path.

## Test plan (for q-a-tests.md once this lands)

### Sender side

- File at `outbox/alice/foo` delivers to alice with subject `foo`;
  file stays in place after delivery; future edits propagate.
- File at `outbox/alice/foo` with extra `to: bob` inside delivers
  to both alice and bob; subject is still `foo`.
- File at `outbox/alice/foo` with redundant `to: alice` inside
  delivers to alice exactly once (no duplicate).
- Binary file at `outbox/alice/photo.jpg` (no text header): not
  mutated on disk; wire delivery sends whatever the body layer
  supports for non-text bodies (may be handled as opaque bytes or
  may be rejected by the body-size guard — out of scope here,
  documented either way).
- Deleting the file (`rm outbox/alice/foo`) triggers the normal
  deleted-file cleanup; alice receives a delete notification.
- Moving the file to a different contact folder (`mv outbox/alice/foo
  outbox/bob/foo`) is seen as "deleted from alice, new file for
  bob" — alice gets a delete, bob gets a new deliver.
- `outbox/alice/foo` AND `outbox/foo` coexist with distinct state
  entries — no cross-contamination.
- Nested dir `outbox/alice/projects/q2` delivers as
  `inbox/projects/q2` on alice's side; intermediate directories
  created.
- Deeply nested dir `outbox/alice/projects/2026/q2/plan` works
  recursively.
- Contact-named dir with no contact behind it (e.g. user had
  contact "alice," renamed to "alice-smith," forgot to move the
  folder): logged as unknown contact, file not sent, state left
  alone.
- Non-contact-name dir (`outbox/drafts/`): existing once-per-
  session warning fires as today.

### Receiver side

- Incoming subject containing `/` creates the intermediate
  directories under `INBOX` and writes the file at the full
  relative path.
- Subject containing `..` is rejected (or the component dropped —
  pick one and document).
- Subject with a leading `/` is rejected.
- Subject with a leading-dot component is rejected.
- Duplicate relative paths disambiguate via #315's short-id
  suffix (on the basename, not on a path component).
- Inbox attribute updates (#306) target by message_id, not path,
  so a rename on the sender's side doesn't orphan updates.

## Source

User request 2026-04-20; design refined over two rounds of feedback
on 2026-04-20.

## Related

- **#369** — Android UI for contact folders.  Blocked on this
  landing daemon-side first.

## Status

Open.
