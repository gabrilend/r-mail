# #214 — Contact-named outbox folders: drop a file in, it sends to that contact

## Current Behavior

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

## Intended Behavior

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
do — body edits (#207), attachments, glob expansion (#204),
missing-file markers (#202), delete propagation. The only
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
   there's a specific, visible reason (glob expansion from #204,
   missing-file markers from #202 — both under named comment
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
plaintext and greppable (no hashing per the #505 reversal), and
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
clobbering. The #814 duplicate-filename logic (append a short
`-<message_id_prefix>` when different message_id, merge when same)
already does the right thing when extended to paths — two
different message_ids with the same *relative path* become
`projects/q2-plan.md` and `projects/q2-plan-<short>.md`.

### Rename and deletion

Post-#505 reversal: contact renames are a user-serviced operation.
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

## Suggested Implementation Steps

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
blank/comment tolerance (#202), glob expansion (#204), everything.

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
- Duplicate relative paths disambiguate via #814's short-id
  suffix (on the basename, not on a path component).
- Inbox attribute updates (#207) target by message_id, not path,
  so a rename on the sender's side doesn't orphan updates.

## Source

User request 2026-04-20; design refined over two rounds of feedback
on 2026-04-20.

## Related

- **#822** — Android UI for contact folders.  Blocked on this
  landing daemon-side first.

## Status

**Built 2026-11-05** (branch `claude/214-contact-folders`, stacked on
#215's branch because it changes the same delivery code).  Everything in
the test plan above is covered by `scripts/test-contact-folders.sh`,
except where Decisions below say otherwise.

## Decisions

Made while building; each can be changed later at the cost named.

1. **Only a subject holding `/` is a path.**  A subject without one is
   named exactly as before, byte for byte (renaming and numbering
   included), so nothing changes for mail between older daemons.  An older
   receiver given a path keeps only its last name, as it always did.
2. **A subject that cannot be a safe path is refused, not flattened**
   (the issue left "rejected, or the component dropped" open): `400`,
   nothing written, a log line naming the reason.  Refused: an absolute
   path; an empty name (`a//b`, `a/`); `.` or `..`; a name starting with
   `.`; any control byte, NUL and DEL included; a name over 255 bytes; more
   than 16 levels; over 1024 bytes in all.  Within a name, `\` becomes `_`
   and a space `-` (a flat subject's spaces are dashed the same way).  One
   function (`mailpath.relative`) decides, on both sides: the sender holds
   back any file whose path it would refuse, and says so once a session,
   so an honest sender never sends one to be refused and retried.
3. **Folders are made one level at a time, by two separate checks**:
   any folder on the way that is a symbolic link is refused, and after
   making them the real path (`pwd -P`) must lie inside the inbox.  Either
   check alone keeps the message inside; the test checks each refusal's
   own reason, so removing either check fails it.  Names are passed as
   `./<name>` so one starting with `-` is never read as an option.
4. **A file holding a folder's name** (the owner's `inbox/projects` is a
   file): the message is saved without its folders, beside it, rather
   than refused, so it is not lost and the owner's file is untouched.  A
   folder that cannot be made for another reason (permissions, a full
   disk) answers `500`, so the sender sends it again later.
5. **What counts as a contact folder**: a folder directly in the outbox
   named exactly as a contact that may be sent to.  Not a listen-only
   contact (#420; it receives nothing), and not this mailbox's own name:
   both are warned about as stray folders, as before.  A folder whose name
   is no longer a contact but which the outbox record still tracks (the
   contact renamed) stays tracked: its messages wait, logged as for an
   unknown contact, instead of being taken for deleted.
6. **Inside a contact folder**: regular files at any depth; hidden files
   and folders, and symbolic links, are skipped (`find -type f`), so a
   link is never followed out of the folder.  Undo: allow links to files.
7. **The record's key is the path from the outbox** (`alice/q2-plan`), and
   the subject the path below the contact folder (`q2-plan`), as designed
   above.
8. **The folder's contact deleting their copy**: the file is removed from
   the folder, as the last recipient's delete removes any outbox file,
   unless its `to:` lines still name someone else.  Then it stays for
   them, the record notes `folder_left`, and the folder's contact is not
   sent it again; it goes once those others have deleted it too.  Taking a
   recipient out of a folder file never deletes the file, never drops its
   `attach:` lines (the folder's contact owns them all), and writes the
   file only when a `to:` line was actually removed (it may be a photo).
9. **A `to: <own name>` inside a contact folder file** delivers to your own
   inbox flat, under the file's name, not in folders.
10. **No new watches.**  The outbox watcher sees only the outbox itself,
    so a file added inside a contact folder is found by the next timed
    sync (within about a minute while the contact answers) or by any
    change directly in the outbox.  Watching each contact folder needs a
    watch per folder, and the macOS watcher keeps one open descriptor per
    watch in a fixed table of 16 (`rmail_kqueue.c`), so that is left as
    open question 1.
11. **The receiver's inbox**: messages kept in folders are tracked by the
    inbox record and checked by their path each sync (deleting one there
    tells the sender, as for any inbox file).  The once-a-session note
    about a folder in the inbox no longer says rmail never makes one.
    Folders emptied by deletes or moves are left in place.
12. **Not done here**: the phone's outbox listing and the Android client
    see only files directly in the outbox (#822).  Whether a body that is
    not text (a photo dropped in a folder) arrives intact is the wire's
    question, as the issue says; the sender's file is never changed.

## Tested

- `scripts/test-contact-folders.sh` (new): two daemons on loopback, a
  sender with a contact folder holding a plain note, a nested
  `projects/2026/q2-plan`, a file naming the folder's contact again, a file
  with `to:` its own sender, a `hello` beside a flat `hello`, a binary
  file, hidden files, a path with a line break, and a non-contact folder;
  then an edit, a move and a delete on the sender's side, and two deletes
  on the receiver's.  Then a stand-in contact sends the receiving daemon
  15 hostile subjects, each refused with its own reason and nothing
  written (also nothing written through a symbolic link out of the inbox),
  5 that must be accepted (16 levels, a leading `-`, spaces, a file in the
  way, a flat `a\b`), and a fuzz pass of 600 random subjects checked
  against the rule written again in the test, then that no link was made,
  every inbox folder resolves inside the inbox, nothing appeared outside
  it, and the daemon still answers.  All pass (about 2.5 minutes).
- The same script against #215's branch (before this): 29 checks fail
  and 8 pass; every hostile subject is accepted there (the old receiver
  keeps only the last name, so nothing escaped, but nothing was refused
  either).  Planted faults, one at a time: without the `..`
  check, without the symbolic-link check, and without the `folder_left`
  check, the script fails each time.
- The fifteen existing test scripts that run two daemons pass unchanged.

## Open questions

1. Watch contact folders (and the folders inside them) so a dropped file
   is sent at once, at the cost of reworking the macOS watcher's fixed
   table?
2. A path subject a receiver refuses is retried by its sender forever.
   Only a broken or hostile sender sends one; should the receiver instead
   save it flat under its last name, so nothing is retried?
3. Remove a folder in the inbox once the last message in it is deleted?
4. Should a note to yourself from a contact folder keep its folders too
   (decision 9)?
