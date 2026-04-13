# #328 — Store rapidly-updated progress files in RAM

## Problem

Attachment progress files (receiver's consent file during transfer, sender's
`transfers` file) are rewritten on disk after every chunk. This causes
unnecessary disk writes for what is ephemeral status information.

## Ideas

- Store progress files in `/tmp` (RAM-backed tmpfs) with symlinks from the
  expected location.
- For the receiver's consent/progress file: use a `continue` line that the
  user can delete to cancel. The file is regenerated in RAM each time it
  needs updating. If it doesn't exist (e.g. after reboot), the transfer
  resumes and recreates it.
- For the sender's `transfers` file: symlink to `/tmp/rmail-transfers`,
  regenerated as needed.
- Must preserve the ability to cancel a transfer by deleting/editing the file.

## Source

From inline comments in `docs/attachments.md`.
