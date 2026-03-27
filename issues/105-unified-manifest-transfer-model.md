# Unified manifest-based transfer model for all paths

Currently, daemon-to-daemon attachment transfers use a manifest model:
consent → manifest exchange → random chunk delivery → checksum verification.
This gives resumable, idempotent transfers that survive interruptions.

The phone-to-server and server-to-phone paths use a simpler sequential model:
upload/download chunks in order, no manifest, no resume. If the transfer is
interrupted, it starts over.

## Proposal

Unify all three paths (daemon↔daemon, phone→server, server→phone) to use the
same manifest-based model:

1. **Sender/requester gets file info**: size, total chunks, per-chunk checksums
2. **Receiver checks what it already has**: partial downloads from previous
   attempts, chunks already on disk
3. **Receiver requests only missing chunks**: in random order to enable
   parallelism and avoid head-of-line blocking
4. **Each chunk is independently verifiable**: checksum per chunk, not just
   per-file
5. **Transfer is idempotent**: requesting a chunk twice is harmless, receiving
   a duplicate is detected and skipped

## Benefits

- Resumable transfers on all paths (phone loses WiFi mid-download, reconnects
  later, picks up where it left off)
- Natural parallelism (request N random chunks concurrently)
- Duplicate detection (two threads requesting the same chunk is fine)
- Same code path everywhere — fewer bugs, one model to understand

## Status

Not yet implemented. The phone currently uses sequential chunked downloads
(issue #104's server parallelism would also help here).
