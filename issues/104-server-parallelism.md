# Server parallelism

The Lua daemon is single-threaded. It processes one incoming connection at a
time in its main loop (`server:accept()` → process → repeat). While it handles
one request, all other incoming connections queue up at the OS level.

This means:
- Parallel chunk downloads from the phone can't actually run in parallel on the
  server — they serialize behind the main loop.
- Multiple contacts connecting simultaneously block each other.
- The phone's 4 concurrent download coroutines just hide TCP setup latency,
  not actual I/O parallelism.

## Options

1. **`socket.select()` for concurrent request handling** — the daemon already
   uses this pattern in `http_post_batch()` for outgoing connections. The main
   loop could accept multiple clients and service them interleaved using
   non-blocking I/O. Most complex but most correct.

2. **Thread pool via Lua lanes or similar** — Lua has no built-in threading,
   but libraries like `lua-llthreads2` or `Lanes` can spawn OS threads.
   Adds a dependency.

3. **Pre-fork model** — spawn N worker processes that each `accept()` on the
   same socket. Simple, but sharing state (inbox.json, outbox.json) between
   workers is messy.

4. **Separate the sync cycle from request handling** — the main bottleneck is
   that the sync cycle (outbox delivery, inbox checks, address notifications)
   runs in the same thread as incoming request handling. Moving the sync cycle
   to a background timer that doesn't block `accept()` would unblock request
   handling during sync.

Option 4 is probably the best first step — it's the least invasive and solves
the most common case (phone requests timing out because the server is mid-sync
delivering messages to a slow contact).

## Connection pooling (client side)

Currently, every request (including each 256KB chunk download) opens a new TCP
connection: `Socket()` → connect → TLS-equivalent handshake → one request →
close. For a 2.3GB file at 256KB chunks, that's ~9000 connections.

A connection pool would keep N persistent sockets open to the server, reusing
them for multiple requests. Each socket is authenticated with the device's
token (AES key = SHA-256(token)), so the pool is per-server, per-device.

This requires the server to support keep-alive connections — currently it
closes after each response. The server would need to loop on a connection:
accept → identify sender (trial decryption of first frame) → handle request →
send response → wait for next frame (with timeout) → repeat.

This pairs naturally with `socket.select()` — the server would track multiple
open connections and service whichever has data ready.
