# Server concurrency with coroutines

The Lua daemon is single-threaded. It processes one incoming connection at a
time in its main loop (`server:accept()` → process → repeat). While it handles
one request, all other incoming connections queue up at the OS level.

This means:
- Parallel chunk downloads from the phone can't actually run in parallel on the
  server — they serialize behind the main loop.
- Multiple contacts connecting simultaneously block each other.
- A long chunk transfer (hundreds of chunks) blocks ALL other daemon activity
  for the entire duration — no incoming messages, no phone syncs.

## Approach: coroutines + socket.select()

Lua has built-in coroutines (`coroutine.create/resume/yield`) available in
every version we support (5.1, 5.2, 5.3, 5.4, LuaJIT). Coroutines are
cooperative (not preemptive) — they run on a single OS thread but can
interleave at yield points.

For rmail this is ideal. The bottleneck is network I/O (waiting for TCP
responses), not CPU. Coroutines + `socket.select()` let us:

1. Start sending a chunk to contact A
2. While waiting for A's response, `yield` and `accept()` an incoming phone
   request
3. Handle the phone request, send response
4. `yield` back, check if A's response arrived
5. Continue sending chunks to A

The daemon already uses this pattern in `http_post_batch()` for outgoing
connections (non-blocking sockets, `socket.select()`, interleaved I/O). The
change is extending it to the main loop so incoming and outgoing connections
are all multiplexed in one select loop.

### Architecture

```
main loop:
    while true do
        readable, writable = socket.select(all_sockets, all_pending, 0.5)
        for each readable socket:
            if it's the server socket → accept new connection, create coroutine
            if it's a client socket → resume its coroutine with the data
        for each writable socket:
            resume the coroutine that was waiting to write
        check sync timer → if due, start sync as a coroutine
    end
```

Each connection (incoming request or outgoing chunk transfer) is a coroutine.
When it needs to read or write on a socket, it registers interest with select
and yields. The main loop resumes it when the socket is ready.

### Why not true parallelism (for now)

True OS-level parallelism (effil, pthreads, C extension) would allow using
multiple CPU cores. But:
- rmail's workload is I/O-bound, not CPU-bound
- Coroutines are built into Lua — no dependencies
- Shared state (inbox.json, outbox.json, contacts) is simpler without locks
- The complexity of thread-safe state management isn't justified yet

If CPU becomes a bottleneck (e.g., AES-GCM encryption of many simultaneous
large transfers), we can add true parallelism later.

## Important constraint: ongoing transfers must not be interrupted

Currently, `send_next_chunks()` runs synchronously inside the sync cycle and
blasts through all missing chunks in one call. With coroutines, chunk transfers
become their own coroutines that run across many iterations of the main loop.

We must ensure that:
- An ongoing chunk transfer is NOT interrupted or restarted by the next sync
  cycle — the transfer coroutine runs to completion independently
- The sync cycle initiates transfers but doesn't own their execution
- If the sync cycle detects a transfer is already running for a given
  attachment, it skips it rather than starting a duplicate
- State files (chunks-outgoing.json) are only written by the coroutine that
  owns the transfer, not by the sync cycle while chunks are in flight

## Connection pooling

Currently every request opens a new TCP connection. With coroutines, we can
keep connections alive:

1. Server accepts a connection, identifies the sender (trial decryption of
   first frame)
2. Subsequent frames on the same connection try the sender's key FIRST (not
   full trial decryption) — optimization since we already know who's talking
3. Handles request, sends response
4. Waits for the next frame — connection stays in the select loop
5. Connection closes when the client sends an explicit "end of session" signal
   (not a timeout — the client decides when it's done)

This eliminates per-request TCP handshake and AES key derivation overhead.
Each connection is authenticated with its device/contact token, so the pool
is naturally per-sender.

On the Android client side, a matching change: keep the TCP socket open after
each request and reuse it for the next chunk download. The `RmailClient` would
hold a persistent socket instead of creating one per `request()` call.

## Concurrent chunk downloads on Android

Parallel chunk downloads to the phone are safe and should be re-enabled:

- Each chunk writes to a non-overlapping region: `offset = chunk_index * chunk_size`
- The destination file is pre-allocated to full size
- Each chunk is checksum-verified before writing
- Whole-file checksum verified after all chunks land
- `RandomAccessFile.seek()` + `write()` is safe for non-overlapping regions

The previous corruption bug was likely not from concurrent writes but from
a different issue (response parsing or chunk size mismatch). The daemon-to-
daemon path uses separate temp files per chunk with no corruption issues.

Dynamic concurrency: calculate max in-flight chunks from available heap:
`max_concurrent = (Runtime.maxMemory() * 0.5) / chunk_size`
This adapts to the device — a phone with 256MB heap gets ~500 concurrent
256KB chunks, a phone with 512MB gets ~1000. Leave headroom for normal app
operation.

## Status

- [ ] Server: coroutine-based main loop with socket.select()
- [ ] Server: keep-alive connections (try sender's key first on subsequent frames)
- [ ] Server: explicit session-end signal instead of timeout
- [x] Android: concurrent chunk downloads with dynamic concurrency, per-chunk
      checksums, whole-file verification, and cancellation support
- [ ] Android: persistent RmailClient socket with connection reuse
- [ ] Daemon-to-daemon: persistent connections for chunk transfers
