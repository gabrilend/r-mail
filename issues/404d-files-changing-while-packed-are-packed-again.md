# #404d — A file that changes while it is being packed is packed again, not sent torn

## Status

Open, 2026-09-29.  Sub-issue of #404.

## Current Behavior

`compress_attachment` runs `zip` on the file or folder named by an
`attach:` line and records the zip's checksum and size.  `zip` reads the
source from start to end; if the owner (or a program) is still writing
the file, the zip holds the first part of the old content and the last
part of the new — a torn copy — and nothing notices.  The recipient gets
a file that never existed.

Also: the success check reads `os.execute`'s first result as true/false.
That is right on Lua 5.2 and later; on Lua 5.1 and LuaJIT it is a number,
and a failing `zip` (non-zero exit) still counts as success.

## Intended Behavior

- Before `zip` runs, record a fingerprint of the source: for every file
  and folder under it, its path, size in bytes and modification time
  (`find <src> -printf '%p %s %T@\n'`).  After `zip`, take it again.
- Different → the zip is deleted, the log says the file changed while it
  was being packed, and the pack fails with the reason `changed`.
- Callers retry rather than give up:
  - a new attachment (`sync_outbox`) is not recorded, so the next cycle
    packs it again (as any failed pack already is);
  - a re-pack of a lost zip (`send_next_chunks`) keeps the transfer and
    tries again next cycle, instead of cancelling it as it does for a
    missing source.
- `zip`'s exit status is read with `upload.succeeded` (from #404a), right
  on every Lua.

## Suggested Implementation Steps

1. `upload.fingerprint(path)` — the listing above, as one string.
2. `compress_attachment`: fingerprint before and after; return
   `nil, "changed"` on a difference, `nil, "zip-failed"` when zip fails.
3. `send_next_chunks`: on `changed`, keep the transfer and move on.
4. Test `scripts/test-torn-pack.sh`: a real sending daemon whose `zip` is
   a stand-in (first on its `PATH`) that appends to the source file before
   calling the real `zip`.  The log must say the file changed, no request
   may be sent, and when the stand-in stops changing the file the next
   cycle sends it.

## Related

- Parent: #404.
