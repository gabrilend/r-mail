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
that directory as an outbox message addressed to `<NAME>` — no
`to:` line required. The directory name *is* the recipient.

```
~/mail/outbox/
    alice/              ← directory named after contact "alice"
        quick-note      ← sent to alice; body = file contents, subject = "quick-note"
        birthday-plan   ← sent to alice
    hello-world         ← regular outbox file with `to:` lines as usual
```

Messages written this way are fully equivalent to a file in
`outbox/` whose header reads `to: alice\n\n<body>`. All existing
pipeline features — body edits (#306), attachments, delete
propagation, glob expansion (#362), missing-file markers (#363) —
should work identically.

## Design details

### Directory name matching

At the top of `sync_outbox`, after loading contacts, build a set of
contact names. For each subdirectory directly inside `OUTBOX`:

- If the subdirectory name matches a contact → treat as a
  "contact folder." Enumerate its regular files and queue each as
  a message to that contact.
- If the subdirectory name does **not** match a contact → fall
  through to the existing "ignoring directory" warning (once per
  session, as today).

Matching is exact, case-sensitive — same as how `to:` lines
resolve today.

### State keying

Outbox state is currently `state[filename]` keyed by basename. For
files inside contact folders we need a key that survives a basename
collision between `outbox/hello` and `outbox/alice/hello`. Options:

1. **Relative path** as the state key: `"alice/hello"` vs `"hello"`.
   Clean, unambiguous, sorts nicely in the state file. Requires
   updating the key convention across every `state[name]` lookup
   in sync_outbox.
2. **Hash the path** — unnecessary given the #348 reversal; keep
   things plaintext and greppable.

Go with option 1. The state key becomes the path-relative-to-OUTBOX
(with `/` as the separator). Files in the outbox root keep their
plain-basename keys; files in a contact folder get `<contact>/<name>`.

### Header parsing inside contact-folder files

A file inside `outbox/alice/` doesn't *need* a `to:` line. Three
cases:

1. **No `to:` line (the normal case):** recipient = directory name.
   Parser treats the whole file as body (after the usual blank/
   comment handling from #363). `attach:` lines at the top still
   work — the header block exists, it just has no `to:` lines.
2. **`to:` line matching the directory name:** redundant but
   harmless; recipient is still the directory's contact. No
   warning — user explicitly repeated themselves, that's fine.
3. **`to:` line naming a *different* contact:** ambiguous. Two
   options:
   - Directory wins, `to:` ignored with a clear warning.
   - Error: refuse to process, mark the file with a
     `// AMBIGUOUS RECIPIENT: directory says <dir-name>, to: says
     <to-name>` comment, same pattern as the #363 missing-
     attachment marker.

   Lean toward the **error-with-marker** approach. Silent
   precedence is a footgun; the user may have moved a file into
   the wrong folder and still expects the `to:` line to route it.

### Filename becomes the subject

The filename — with the directory stripped — is the subject on
the receiver's side. `outbox/alice/quick-note` lands in alice's
inbox as `quick-note`, same as if the user had written
`outbox/quick-note` with `to: alice`. Subject conversion (spaces
→ dashes, duplicate handling per #315) is unchanged.

### Attachments still work

An `attach:` line inside a contact-folder file resolves the same
way it does in a regular outbox file: relative to the current
working directory (user-facing), with `~` expansion. Glob
expansion (#362) and the missing-file marker (#363) work
identically.

### Nested directories

Only the first level matters. `outbox/alice/` is a contact folder;
files directly in it get routed to alice. `outbox/alice/drafts/`
is a subdirectory *inside* a contact folder — fall through to the
existing "directory inside this path" warning path, treated as
ignored.

Explicitly non-goal: per-contact outbox subfolders for organisation
(e.g. `outbox/alice/drafts/` or `outbox/alice/2026-04/`). That adds
complexity users can get by renaming files with prefixes if they
want.

### Directory detection side of the existing warning

`list_files` (`rmail.lua:294`) currently logs the "ignoring
directory" warning for every dir found under OUTBOX. After this
change, that warning should only fire for directories whose names
*don't* match a contact. The contact-folder path runs separately
(not through `list_files`) and doesn't trigger the warning.

Legacy behaviour preserved: a user with a directory named something
non-contact-ish (e.g. `outbox/drafts/`, `outbox/templates/`) still
sees the one-line warning, same as today.

### Contact rename

Post-#348 reversal: contact renames are a user-serviced operation.
If `outbox/alice/` contains in-flight messages and the user renames
`alice` → `alice-smith` in `contacts`, two things happen:

1. The state entries keyed by `alice/<filename>` reference a
   recipient name ("alice") that no longer exists. Same symptom as
   a `to: alice` line pointing at a nonexistent contact: logged as
   unknown contact, skipped.
2. The user fixes it by `mv outbox/alice outbox/alice-smith` and
   running `sed -i 's|"alice/|"alice-smith/|g; s/"alice"/"alice-smith"/g' .state/outbox.json`.

Documented alongside the existing rename recovery recipe in the
user-facing docs, wherever that lands.

### Android client

The Android app's outbox UI currently lists files at the top level
of the outbox directory. Contact folders should either:

- Be surfaced as a grouping (expandable "alice" folder in the UI).
- Be rolled into the flat list with the contact as a visible badge.
- Ignored for now; daemon-side feature only; Android support
  follows in a separate issue.

Lean toward **ignored for now**. Daemon-side support lands this
issue; Android surfacing is its own design conversation (does the
user even *want* to manage contact folders from the phone, or is
this a desktop workflow?).

## Non-goals

- **Recursive contact folders** (`outbox/alice/2026/` etc.). One
  level only.
- **Inbox-side mirror.** Per-contact inbox folders (`inbox/alice/`)
  are a separate feature worth discussing but not in scope here.
  This issue is about the sender-side workflow.
- **Per-contact attachments dir.** Same — separate concern.
- **Auto-creating the directory** when a contact is added. User
  creates the folder when they want it; no daemon-side auto-
  management.

## Implementation sketch

Rough order of changes in `sync_outbox`:

1. Load contacts (already done).
2. Enumerate `OUTBOX` direct children (not via `list_files`; need to
   distinguish files from subdirs). Use a small helper that returns
   `({files}, {subdirs_matching_contacts}, {subdirs_other})`.
3. For each subdir-matching-contact, enumerate its files; treat
   each as a "virtual outbox entry" with:
   - state key = `<contact>/<filename>`
   - path on disk = `OUTBOX/<contact>/<filename>`
   - implicit `to: <contact>` prepended at parse time
4. Run the existing sync loop over the combined set (flat files +
   virtual entries).
5. For `subdirs_other`, log the "ignoring directory" warning via
   the existing once-per-session mechanism.

`parse_outbox_file` stays as-is; the implicit `to:` is injected
*before* parsing (the caller prepends `to: <contact>\n` to the text
it hands to the parser). That keeps the parser honest: it still
only sees explicit header lines, and the header-robustness work
from #363 continues to apply.

## Test plan (for q-a-tests.md once this lands)

- File in `outbox/<contact>/foo` gets sent to `<contact>` with
  subject `foo`; normal delivery flow runs.
- File in `outbox/<non-contact-name>/foo`: not sent; once-per-
  session "ignoring directory" warning; file untouched.
- Top-level `outbox/foo` with a `to:` line still works unchanged.
- `outbox/alice/foo` AND `outbox/foo` coexist with distinct state
  entries — no cross-contamination.
- Attachments inside a contact-folder file queue correctly
  (glob expansion, missing-file markers, etc. still work).
- `to:` line inside a contact-folder file pointing at a *different*
  contact gets the `// AMBIGUOUS RECIPIENT:` marker.
- `to:` line inside a contact-folder file matching the folder
  works silently (no warning).
- Nested `outbox/alice/drafts/`: not recursed; treated as "ignored
  directory inside contact folder" (or just ignored — pick one and
  log once per session).
- Deleting a file inside `outbox/alice/`: existing delete-
  propagation works via the relative-path state key.
- Renaming the contact: state orphans; `sed` recovery works the
  same as for top-level files.

## Source

User request 2026-04-20.

## Status

Open.
