# #411 — Saving contacts from the phone keeps the file's comments

## Status

Open, 2026-10-02.  Found by the documents-against-code audit
(`notes/audit-docs-against-code-2026-10-02.md`, §1.7).  The owner, on
tokens reaching the phone and comments being lost: "that first part is
expected, the second part is not! What the heck."

## Current Behavior

The phone is sent the contacts in canonical form
(`serialize_contacts_canonical`: contacts sorted by name, fields sorted,
no comments) during sync, edits that, and may post it back
(`handle_api_post_contacts`), which writes the posted text over
`contacts` as it is.  So every `//` comment, blank line and the person's
own ordering is lost on any save from the phone (checked by hand,
2026-10-02).

## Intended Behavior

A save from the phone changes only the entries that changed.  Comments,
blank lines and order stay as the person wrote them; a new contact is
appended; a removed contact's lines are removed with the comment lines
directly above it.

## Suggested Implementation Steps

1. Parse `contacts` keeping each line's kind (entry field, comment,
   blank) and the entry it belongs to.
2. Apply the phone's changes to that list; write it back.
3. Test: a contacts file with comments and blank lines, a phone save
   that edits one contact's address and adds one; every comment and
   blank line is where it was.

## Related documents

- `notes/audit-docs-against-code-2026-10-02.md`
- `docs/.templates/android-instructions.md`
