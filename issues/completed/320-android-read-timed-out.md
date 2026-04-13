# #320 — Investigate "read timed out" error on Android

## Problem

An intermittent "read timed out" error appears on Android and goes away on
the next sync cycle. Likely a transient network timeout during sync.

## Action

Investigate the cause — is it a server-side delay, a network hiccup, or a
too-aggressive timeout setting on the client? Determine if the timeout
value needs adjusting or if the error is harmless and the message should
be softened.

## Source

From `rmail-android-read-timed-out-error`.

## Status

Shipped.

### Root cause

The error came from `java.net.SocketTimeoutException` surfacing
verbatim through `SyncResult.Error.message`. The Android
`RmailClient` used `soTimeout = 10_000` on reused persistent
connections — aggressive for a daemon sync that can do real work
(attachment probes, batch delivery, living-message updates). When
the server was transiently slow the client timed out; the
`request()` loop retried once on `IOException` and if the second
attempt also timed out, the raw exception bubbled up. The next
sync cycle almost always succeeded (server had caught up), so
users saw a scary red "Read timed out" briefly and then nothing.

### Fix

Two changes in the Android client:

1. **Raised the read timeout to 30 s** in `RmailClient.ensureConnected()`
   (previously 10 s). The 5 s connect timeout is unchanged — that's
   for the TCP handshake, which shouldn't take long regardless of
   server workload. 30 s is a better balance: rare to hit when things
   are working, still fast enough to surface a truly dead server
   within one sync cycle.
2. **Translated raw network exceptions into friendly messages** in
   `SyncManager.friendlySyncError()`. A `SocketTimeoutException`
   becomes `"server didn't respond in time — will retry"`, a
   `ConnectException` becomes `"server not reachable — will retry"`,
   `UnknownHostException` and decryption failures each get their
   own short explanation. Fallback is the raw message for anything
   unrecognised.

The user's mental model now matches reality: "the app says it'll
retry, and then it retries" instead of "something called a Read
timed out."

### What this does *not* change

- The retry cadence is unchanged — still the normal sync interval
  (foreground poll or WorkManager cycle), not a special fast-retry.
- The error still surfaces in the red box so the user knows sync
  isn't happening right now; the message is just friendlier.
- If the server is genuinely slow for minutes, the user will see
  the message each cycle. That's the correct signal — they should
  look at the daemon.
