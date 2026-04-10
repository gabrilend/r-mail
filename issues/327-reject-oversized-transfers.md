# #327 — Reject in-progress transfers that exceed expected size

## Problem

The `Expected size` in attachment consent requests is self-reported by the
sender and not verified during transfer. A malicious or buggy sender could
stream far more data than declared.

## Fix

Track cumulative bytes received during a chunked transfer. If total exceeds
the declared expected size (with a small tolerance for compression overhead),
abort the transfer, clean up partial chunks, and notify the sender.

## Source

From inline comment in `docs/attachments.md`.
