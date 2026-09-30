# #404d — A file that changes while it is being packed is packed again, not sent torn

## Status

Completed 2026-09-29.  Sub-issue of #404.  Covered by
`scripts/test-torn-pack.sh` (all cases pass; against the code before this
change, both of its checks fail — the torn copy was offered).

## Current Behavior

Before an attachment is offered, the sending daemon packs the file or
folder named by an `attach:` line into a zip (`compress_attachment`).
`zip` reads the source from start to end; if something is still writing
it, the zip would hold the start of the old content and the end of the
new — a file that never existed.

- **Fingerprint before and after.**  `upload.fingerprint(path)` lists every
  file and folder under the source (or the file itself) with its size in
  bytes and its modification time to the fraction of a second
  (`find <path> -printf '%p %s %T@\n'`), as one string.  It is taken
  before `zip` runs and again after.
- **A difference throws the zip away.**  The zip is deleted, the log says
  `packing <path>: it changed while it was being packed -- will pack it
  again next cycle`, and `compress_attachment` returns `nil, "changed"`.
- **Every failure has a reason.**  `compress_attachment` returns
  `(zip path, SHA-256, packed size)` or `nil` and one of `"missing"`
  (nothing to fingerprint), `"zip-failed"` (zip exited with an error or
  wrote nothing; the zip is deleted and logged), `"changed"`.
- **Callers try again rather than give up.**
  - A new attachment (`sync_outbox`): not recorded, so the next cycle
    packs it again; the log line names the reason.
  - A re-pack of a zip that was lost (a reboot wiped the pending folder)
    in `send_next_chunks`: on `"changed"` the transfer is kept and the
    loop moves on; the next cycle packs again.  A missing source still
    cancels the transfer, as before.  (This branch is checked by reading;
    the test drives the first caller.)
- **zip's exit status is read right on every Lua** (`upload.succeeded`,
  from #404a).  The old `if not ret` counted a failing zip as success on
  LuaJIT, whose `os.execute` returns a number.
- The `upload` table is now declared above `compress_attachment`, its
  first user (the main chunk is at Lua's 200-local ceiling, so helpers go
  in that one table).

### Not changed

The declared size in the request (`expected_size`) is measured with
`du -sb` just before packing, outside the fingerprint window.  A file that
grows between that measurement and packing is offered with the smaller
size and refused by the receiver as oversize (#327) — loud, not torn.

## Intended Behavior

A file written to during packing is never sent; it is packed again once
it holds still.  (Built as above.)

## Suggested Implementation Steps

1. `upload.fingerprint`; declare `upload` above `compress_attachment`.
2. `compress_attachment`: fingerprint before and after; reasons on
   failure; `upload.succeeded` for zip.
3. `send_next_chunks`: keep the transfer on `"changed"`.
4. `sync_outbox`: name the reason in the "failed to compress" log line.
5. Test `scripts/test-torn-pack.sh`: a real sending daemon whose `zip` is
   a stand-in first on its `PATH` that appends to the source before
   running the real zip while a marker file exists; the receiver learns
   nothing of the torn copy; after the marker is removed the file is
   packed and offered.
6. `docs/.templates/attachments.md`: under "Transfer mechanics".

## Related

- Parent: #404.
- #404a — `upload.succeeded`.
