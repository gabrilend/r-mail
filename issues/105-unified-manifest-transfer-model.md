# Unified manifest-based transfer model for all paths

Currently, the three transfer paths (daemon↔daemon, phone→server, server→phone)
each work differently. This issue unifies them into a single resumable,
verifiable, repairable protocol.

## Protocol

All transfers follow the same steps:

1. **File info exchange**: sender provides size, total chunks, chunk size,
   per-chunk SHA-256 checksums, and whole-file SHA-256 checksum

2. **Manifest exchange**: receiver checks what it already has (partial
   downloads from previous attempts, chunks already on disk) and sends
   a manifest of missing chunk indices

3. **Chunk transfer**: sender sends only the missing chunks. Order is
   randomized to enable parallelism and avoid head-of-line blocking.
   Each chunk is independently verifiable by its checksum.

4. **Per-chunk verification**: receiver verifies each chunk's SHA-256 as
   it arrives. Bad chunks are re-requested (up to 3 retries per chunk).

5. **Whole-file verification**: after all chunks land, receiver computes
   the whole-file SHA-256 and compares against the expected checksum.

6. **Repair on mismatch**: if the whole-file checksum fails despite all
   per-chunk checksums passing (e.g., write corruption, race condition),
   the receiver re-chunks the local file, compares per-chunk checksums
   against the manifest, and re-downloads only the corrupted chunks.
   The whole-file checksum is verified again after repair.

7. **Transfer is idempotent**: requesting a chunk twice is harmless,
   receiving a duplicate is detected and skipped. A transfer can be
   interrupted and resumed at any point — the manifest exchange picks
   up where it left off.

8. **State persists to disk**: both sides write transfer state (which
   chunks have been received/sent) so that restarts don't lose progress.

## Current state of each path

### Daemon → Daemon (attachments)
- Already uses manifest model (consent → chunks → missing list)
- Per-chunk checksums verified on receive
- Resumable across sync cycles
- **Gaps**: no whole-file verification, no repair, state not persisted
  across daemon restarts (chunks-outgoing.json is persisted but
  chunks-incoming.json may lose partial downloads)

### Phone → Server (upload)
- Sequential chunks via /api/upload/start + /api/upload/<id>/chunk/<n>
- NOT resumable: interrupted upload starts over
- No per-chunk checksum verification during upload
- **Gaps**: no manifest exchange, no resume, no verification

### Server → Phone (download)
- Concurrent chunks via /api/attachments/<f>/info + /chunk/<n>
- Per-chunk checksums verified, retry up to 3x
- Whole-file checksum verified after assembly
- Repair on mismatch (re-download bad chunks)
- **Gaps**: not resumable across app restarts (no persisted state)

## Changes needed

### Server side (rmail.lua)
- Persist incoming chunk state across restarts
- Add whole-file verification after all chunks received
- Add repair flow (re-request bad chunks from sender)
- Upload endpoint: accept manifest of already-received chunks,
  skip re-uploading them

### Android client
- Persist download state to disk (which chunks received, checksums)
- On resume: read state, compute manifest of missing chunks, request
  only those
- Upload: compute per-chunk checksums, send manifest with upload start,
  resume interrupted uploads

### Protocol additions
- `GET /api/attachments/<f>/info` already returns per-chunk checksums ✓
- Need: `POST /api/upload/resume` — client sends manifest of chunks
  already on server, server responds with which are missing
- Need: persist transfer state files in .state/ directory

## Benefits

- Resumable transfers on all paths (phone loses WiFi at 80%, reconnects,
  picks up at 80%)
- Natural parallelism (request N random chunks concurrently)
- Duplicate detection (two threads requesting the same chunk is fine)
- Automatic repair of corruption without full re-download
- Same code path everywhere — fewer bugs, one model to understand

## Status

- [x] Server→Phone: per-chunk checksums and verification
- [x] Server→Phone: whole-file checksum verification
- [x] Server→Phone: repair on mismatch (re-download bad chunks)
- [x] Server→Phone: concurrent chunk downloads
- [ ] Server→Phone: persist download state for resume across app restart
- [ ] Phone→Server: per-chunk checksum verification
- [ ] Phone→Server: resume interrupted uploads
- [ ] Daemon→Daemon: whole-file verification and repair
- [ ] Daemon→Daemon: persist incoming state across restarts
- [ ] Unified protocol used by all three paths
