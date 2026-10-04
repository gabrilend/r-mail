# #411 — Saving contacts from the phone keeps the file's comments

## Status

Completed 2026-10-04.  Found by the documents-against-code audit
(`notes/audit-docs-against-code-2026-10-02.md`, §1.7).  The owner, on
tokens reaching the phone and comments being lost: "that first part is
expected, the second part is not! What the heck."

## Current Behavior

The phone is sent the contacts in canonical form during sync and from
`GET /api/contacts` (`serialize_contacts_canonical`: one
`name.key = value` line per field, contacts sorted by name, keys sorted,
no comments), edits that, and posts the whole of it back to
`POST /api/contacts`.  The daemon merges the posted text into the
contacts file instead of writing it over the file:

1. The posted text is cleaned (fields named `endpoints` or `ips`, which
   an old client could echo back as "table: 0x…", are dropped), parsed,
   and written out again in canonical form: that is the target.
2. The current file is parsed and written in canonical form too, and the
   two are compared contact by contact.
3. Only what differs is changed in the file's own lines:
   - a contact that is the same: its lines are not touched;
   - a removed contact: its lines go, with the comment lines directly
     above its first line;
   - a new contact: appended at the end of the file, after a blank line;
   - a changed contact: each changed key's single line is edited in
     place, keeping the spacing before the value; a removed key's line
     is deleted; a new key is added after the contact's last line.
4. Some contacts are written in the file in a shape the canonical form
   does not show: `ip[1]` with no plain `ip` shows as `ip`; `local-ip[N]`
   are renumbered; an `ipv6` line is folded into the address list.  When
   a changed key has no single line of its own, that contact's entry
   lines are replaced by its canonical lines at the place its first line
   was, and the log names the contact.
5. The merged text is parsed and must come out, in canonical form, equal
   to the target.  If the key-by-key edit does not, every changed
   contact is rewritten as a block and checked again, with a warning in
   the log.  If that does not either, nothing is written, the log says
   so, and the phone is answered 500.  A contacts file that quietly
   differed from what the owner saved would send mail to the wrong place.
6. If the merged text equals the file, nothing is written.

After a write, the daemon lines up the `=` signs of each contact's lines
and gathers each contact's lines together (`align_contacts`), as it does
at start-up and whenever the file changes.  So a comment *between* one
contact's own lines does not keep its place — it never did — while
comments and blank lines between contacts do.

## Intended Behavior

As above: a save from the phone changes only the entries that changed.

## Suggested Implementation Steps

- `rmail.lua`: the contacts parser is split out of `load_contacts` as
  `contactfile.parse(text)`, so text that is not yet the file can be read
  the same way; `serialize_contacts_canonical` takes a contacts table.
  The merge lives in the `contactfile` table (one table rather than more
  top-level locals: the main chunk is near Lua's 200-local ceiling):
  `canonical_map`, `lines` (the file tagged line by line: entry, bare
  name, comment, blank), `find`, `edit_in_place`, `replace_block`,
  `remove_contact`, `apply`, `merge`; `handle_api_post_contacts` runs it
  and the read-back check.
- Test: `scripts/test-phone-contacts-save.sh` — a contacts file with
  comments, blank lines and a non-alphabetical order; the stand-in phone
  saves it unchanged (byte for byte the same), changes one address (only
  that line changes), adds a contact (appended), removes one (its lines
  and the comment above go), and changes a contact written as `ip[1]`
  (rewritten as a block, the comment above it kept).
- Docs corrected: encryption guide (tokens on the phone), Android guide
  (tokens), protocol guide (`/api/contacts`).

## Related documents

- `notes/audit-docs-against-code-2026-10-02.md`
- `docs/.templates/android-instructions.md`
