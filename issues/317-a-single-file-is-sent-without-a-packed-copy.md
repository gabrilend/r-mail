# #317 — A single file is sent from where it lies, without a packed copy

## Status

Open.  Filed 2026-10-04 from the ritzmenardi.com shrine: its server
(a Linode with 25 GB of disk) must send an 8.8 GB zip, and today that
needs room for the zip and for r-mail's packed copy of it, ~17.6 GB, and
while a newer zip replaces the old one, double that.

## Current Behavior

Before a file is offered it is packed into a zip in the pending folder
(`compress_attachment`; stored, not compressed, by the shared zip library,
#309), its SHA-256 and piece count are fixed, and pieces are read from
that zip.  The copy exists so the bytes stay the same for as long as the
transfer takes (days, for a large file on a slow line): every piece
carries the whole zip's checksum, fixed when piece 0 goes out (#311b),
so the source must not change underneath it.  A file that changes while
it is being packed is packed again (#311d).

For a file that is already a finished, unchanging thing (a zip of a
website, a video), the copy is the whole cost of sending it a second
time, in disk, and buys nothing the file didn't already have.

## Intended Behavior

A single regular file (not a folder) is sent without being copied.  A
stored zip around one file is three parts: a local header (name, sizes,
CRC-32), the file's bytes unchanged, and a central directory at the end.
So the "zip" can be virtual: its header and directory are computed once,
small, and kept in the pending folder; any piece is assembled on demand
from header bytes, file bytes read at the right offset, and directory
bytes.  The receiver sees exactly the bytes a packed zip would have had,
so nothing changes on its side: its checks (#311b, #311e, #310) still
hold.

What the copy used to guarantee, the sender now checks instead:
- The CRC-32 and the whole-zip SHA-256 are computed by reading the file
  once at offer time (no copy is written).
- The file's fingerprint (size, modification time, and inode, so a file
  replaced by another of the same size is noticed) is recorded then and
  checked before every piece is served.
- If it no longer matches, the file changed: the attachment is *lost*,
  exactly as #314 handles a lost copy (transfers stop, recipients get a
  withdrawal, a note goes under the `attach:` line).

Folders, and files under a size threshold, keep being packed as now:
small files cost nothing to copy, and a folder's zip has many entries to
lay out.

## Suggested Implementation Steps

1. In the shared zip library, a "stored single-file layout": given a path
   and its CRC-32, return the header bytes, the directory bytes and the
   total length; and a reader that returns bytes N..M of the virtual zip.
   Check it against `zip_writer.pack` on the same file: identical bytes.
2. A config key for the threshold (e.g. `attachment_copy_below`, default
   a few MB); above it, single files go virtual.
3. In the outbox record, a packed entry gains a kind: `copy` (as now) or
   `virtual` (source path, fingerprint, header/directory file, checksum).
4. Where pieces are read for sending, a virtual entry reads through the
   layout, after checking the fingerprint; a mismatch goes the #314
   *lost* route.
5. Tests: a virtual transfer of a large sparse file arrives
   byte-identical to a packed one; touching the file mid-transfer stops
   it as lost; replacing it with a same-size file stops it too (inode);
   the pending folder holds only the small header/directory file.

## Open questions

- *The owner, 2026-10-09:* "if the file we want to send is a zip file,
  and it's already chunked... then we should just, skip the chunking
  step. Easy."  A simpler shape than the virtual zip above: an attached
  `.zip` is sent as it is, pieces read from it where it lies, no packing.
  The catch, asked the same day: the receiver unpacks whatever zip
  arrives, so the recipient would get the zip's *contents* (a folder),
  not the `.zip` file itself, which is what the virtual zip keeps.
  Which does the recipient get?
  *Answered 2026-10-09:* "we should make it so that they should get the
  file in whatever format it is in before it's chunked. In this specific
  case, we are taking a zip file, chunking it, and sending those, so it
  rebuilds into a single zip, not a bunch of chunks" — and "how about if
  we point to a manifest file then?"  So: a single file travels as its
  own bytes, in pieces, with a small manifest (the offer) saying what
  the pieces rebuild into — its name, exact size and checksum, and that
  it is one file, not a zip to unpack.  The receiver joins the pieces
  into that file and does not unpack it.  No zip wrapper, virtual or
  real.  (Today's result for a recipient is the same — a single file is
  zipped, then unzipped on arrival — so the change is the sender's disk
  and the receiver's unpacking, not what the recipient ends up with.)
  Folders keep travelling as zips.  Still to settle: what an older
  receiver, which would try to unpack the pieces, is sent.
  *Then, 2026-10-09:* "I don't like the idea of adding a 'kind' field."
  Explained the same day: pieces are byte ranges of one zip, not little
  zips, and the zip is *stored* (no compression), so unpacking it gives
  back the original 8.8 GB zip byte for byte — the receiver already ends
  up with the file as it was.  The only waste is the sender's copy, and
  the virtual zip (Intended Behavior above) removes it with no change to
  the offer and none to the receiver, so older receivers keep working.
  Proposed: build the virtual zip, no new field.  Waiting on the owner.
- Should the threshold default to "always virtual for single files", or
  stay conservative (only large files) until it has run for a while?
- A file modified in place without its modification time changing would
  slip past the fingerprint.  Is a periodic re-hash of the bytes already
  sent (cheap, sequential) worth it for very long transfers?

## Related

- #316 — one packed copy per file across messages (complements this:
  folders and small files still pack).
- #314 — the *lost* route a changed source takes.
- #311b, #311d — the checksums and the changed-while-packed rule.
- #309 — the shared zip library the layout lives in.
