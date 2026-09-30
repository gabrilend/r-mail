# #404a — A symbolic link in a received zip becomes a note, never a link

## Status

Completed 2026-09-29.  Sub-issue of #404.  Covered by
`scripts/test-received-links.sh` (all cases pass; run against the code
before this change, 11 of its cases fail, including the phone reading a
planted link to a secret file).

## Current Behavior

### Before this issue (the problem it solved)

`handle_attachment_chunk` extracted a contact's zip with a bare
`unzip -o`, which recreates symbolic-link entries as real links, and
`upload.file_entry` moved them into `attachments/`.  A symbolic link is a
tiny file whose content is a path; opening it opens whatever that path
names.  A zip holding `x -> ~/.ssh/id_rsa` therefore let the phone read
the owner's private key through `/api/attachments/x`, and handed it to
the `on_package` hook.  A link `d -> /home/you` followed by an entry
`d/.bashrc` could also be written through, depending on the `unzip`
build.

### Now

- **No link is created.**  `upload.unpack_received(zip, extract_dir)`
  replaces the bare `unzip` in the receive path:
  1. It reads the zip's table of contents with `upload.list_entries`
     (`unzip -Z`, the zipinfo listing; first column is the Unix mode, and
     a leading `l` means a link).  The count of entry lines must equal the
     count the zip's header declares, or the zip is refused as
     `unreadable-archive`.
  2. Link entries are left out of extraction (`unzip -x <names>`, each
     name escaped by `upload.unzip_pattern` so `[`, `*` and `?` match
     only themselves).  No link exists at any moment for a later entry to
     be written through.
  3. After extraction, `find <extract_dir> -type l` must find nothing.
     A survivor refuses the transfer (`link-in-archive`).  This is the
     line that catches a link whose name holds a newline: zipinfo prints
     such a name across two lines, so step 1 sees only its first part and
     the exclusion misses — the test proves this path.
  4. For each link, `unzip -p <zip> <name>` gives its stored content,
     which is its target; a note `<name>.symlink.txt` is written at the
     link's place (`upload.link_note`):

         This was a symbolic link to: <target>
         It was not recreated, because a link can point at any file on this computer. If it is valid here, make it by hand.

     Control characters in the target are written as `\xNN`.  A link name
     that is absolute or holds `..` is refused, since its note would land
     outside the extract folder; so is a note name already taken by a real
     file in the zip, and a link whose content cannot be read.
- **Refusal** goes through `upload.refuse_transfer`: the pending folder
  is removed, the consent form leaves the inbox, and the consent record
  becomes `cancel_pending` with `rejection_reason` set, which tells the
  sender to stop.  An `unzip` failure (`extraction-failed`) keeps the old
  answer: 500, chunks kept.
- **Serving.**  `/api/attachments/<name>`, `/info` and `/chunk/<n>` ask
  `upload.refuse_link` first and answer 403 "symbolic links are not
  served", with a log line; the listing (`/api/attachments`) leaves links
  out.  A link the owner makes by hand in `attachments/` is therefore not
  reachable from the phone — intended: the phone only reaches files that
  are really in the folder.
- **Exit statuses.**  `upload.succeeded(cmd)` answers whether a command
  exited 0 on every Lua: 5.1 and LuaJIT return the status as a number
  (so a failure is still "truthy"), 5.2 and later return true or nil.

The owner's reasoning for the note, 2026-09-29: "can we make a .txt file
in the place of symlinks that say "this is a symlink to this directory: "
that way an AI agent, upon trying to figure out why it didn't work, can
examine it and correct it if it's valid. Forcing a recognition check.
Strategem."

### Found and fixed on the way

The phone's attachment listing crashed whenever a folder was in
`attachments/` (every received folder attachment): the directory-listing
helper logs about folders it skips, but it sat above the `log` function
in `rmail.lua`, so `log` was unbound when it was compiled.  The helper
now sits below `log`, with a comment saying why.

## Intended Behavior

A received zip never creates a link; its place holds a note saying where
it pointed; nothing in `attachments/` is served through a link.  (Built
as described above.)

## Suggested Implementation Steps

1. `rmail.lua`, the `upload` table (the main chunk is at Lua's 200-local
   ceiling, so helpers go there): `succeeded`, `list_entries`,
   `unzip_pattern`, `link_note`, `is_link`, `unpack_received`,
   `refuse_transfer`, `refuse_link`.
2. `handle_attachment_chunk`: `upload.unpack_received` in place of the
   bare `unzip`; `extraction-failed` → 500 as before, any other refusal →
   `upload.refuse_transfer`.
3. `handle_api_get_attachment`, `handle_api_attachment_info`,
   `handle_api_attachment_chunk`: `upload.refuse_link` first; the
   request dispatcher says "symbolic links are not served" on 403.
   `handle_api_list_attachments`: skip links.
4. Move the directory-listing helper (`list_files`) below `log`.
5. Test: `scripts/test-received-links.sh`, built on the stand-in contact
   `scripts/lib/fake-contact.lua` (speaks the daemon's encrypted request
   format with a shared key; can ask for consent and accept it the way
   the owner would, by deleting the "deny" line).
6. `docs/.templates/attachments.md` (the tracked source; `docs/*.md` are
   generated from it at install time and are not in git): "What a
   received attachment is not allowed to do".

## Related

- Parent: #404.
- #327 — adds the unpacked-size measurement in front of this step.
