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
