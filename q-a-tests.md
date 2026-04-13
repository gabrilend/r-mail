# QA Test Checklist

Manual test cases parsed from issue files. Update this whenever issues are
created, modified, or completed. When everything is checked off, the system
is ready for deployment as-is.

Work through top-to-bottom — grouped by testing area so you don't have to
jump around.

---

## 1. Daemon startup and dependencies

- [ ] Daemon fails to start if `rmail_inotify.so` is missing
- [ ] Daemon starts cleanly and logs "outbox inotify watcher active"
- [ ] Lua 5.4 `os.execute` return value handled correctly (#100)
- [ ] Service logs write to `/tmp/rmail.log`, not to disk (#205)

## 2. Daemon config and hooks

### Hook config format (#325)
- [ ] Config uses empty string default instead of commented-out hook lines
- [ ] Default orchestrator scripts exist in `scripts/hooks/`
- [ ] Each default script has: argument table, scripting tutorial link, orchestrator hint
- [ ] `${RMAIL_DIR}` resolves correctly in config values

### Helper scripts (#326)
- [ ] `rfield.sh` exists in `helpers/`
- [ ] Docs and scripting tutorial reference the helpers/ location

### rto / rattach helpers (#330, #331)
- [ ] `rto.sh <file> <recipient>...` inserts `to:` lines after the existing header block
- [ ] `rattach.sh <file> <path>...` inserts `attach:` lines after the existing header block
- [ ] Empty/non-existent target file: helpers create it with just the new header lines
- [ ] Existing `to:`/`attach:` ordering is preserved (new lines appended to block, not prepended)

### raccept / rdeny helpers (#332)
- [ ] `raccept.sh <consent-file>` leaves only the `accept` line in the consent file
- [ ] `rdeny.sh <consent-file>` leaves only the `deny` line in the consent file
- [ ] Daemon's `check_consent_pending()` acts on the resulting single-decision file

## 3. Sending messages (daemon outbox)

### Outbox file watching (inotify)
- [ ] Saving a file in the outbox directory triggers immediate sync
- [ ] Deleting or moving a file in the outbox triggers immediate sync
- [ ] Sync cycle's own outbox modifications don't cause a feedback loop (drain works)

### Duplicate filename prevention (#315)
- [ ] Daemon rejects delivery if converted filename matches existing inbox file at destination
- [ ] Duplicate check uses converted filename (after spaces-to-dashes), not raw subject

### Living messages — edits propagate (#306)
- [ ] Edit outbox file body → all recipients receive updated content
- [ ] SHA-256 checksum in outbox.json matches actual file body after edit
- [ ] Update sent to each recipient independently
- [ ] Removing a `to:` line triggers deletion on recipient side, not update
- [ ] Recipient who deleted the message (404) gets removed from outbox.json state

### On_update hook (#306)
- [ ] `on_update` hook runs before inbox file is written
- [ ] Hook receives: sender ($1), file path ($2), new body ($3)
- [ ] Hook stdout replaces saved body; no hook = body applied directly

### Delete/edit race conditions (#323)
- [ ] Interaction matrix built: sender sync first vs receiver sync first
- [ ] All sender/receiver event combinations traced and validated
- [ ] Receiver deletes inbox file, sender edits outbox → file is NOT "undeleted"
- [ ] `handle_deliver_update` returns 404 when the inbox file is missing on disk (even if inbox.json still has the entry)
- [ ] Sender's batch handler treats that 404 as "recipient deleted" and cleans outbox.json accordingly

## 4. Receiving messages (daemon inbox)

### `attach:` paths (#101)
- [ ] Paths with `~` expand to home directory

### Large payloads (#204)
- [ ] Large message sends don't truncate (no partial send bug)

### Chunk handling (#202)
- [ ] Chunk responses parse correctly

## 5. Attachments

### Oversized transfer rejection (#327)
- [ ] Transfer aborted if cumulative bytes exceed declared expected size
- [ ] Partial chunks cleaned up on abort
- [ ] Sender notified of abort

### Auto-body: oversized message bodies (#349)
- [ ] Body ≤ 128 KB: normal deliver, no attachment pipeline involved
- [ ] Body > 128 KB: daemon writes a copy under pending/ named after the subject, compresses, queues attachment_request with auto_body=true, sends stub as the message body
- [ ] Stub body text mentions the attachment filename (e.g. "delivered as attachment my-note")
- [ ] Auto-body attachment lands on receiver at `~/mail/attachments/<subject>` (same name as the inbox stub, different directory)
- [ ] Receiver sees a normal consent form for the body attachment (not a bypass)
- [ ] Retry after a failed deliver reuses the existing att_id (no duplicate compression)
- [ ] Retry continues until receiver consents; after consent, chunk-sender takes over
- [ ] Transfer complete: auto-body temp file under pending/ is removed
- [ ] Transfer complete: no outbox attach: line is stripped (there never was one)
- [ ] Compression failure falls back to the old body_too_large error file
- [ ] `on_send` hook runs on the stub body (not the oversized original)

### Progress files in RAM (#328)
- [ ] Receiver's progress file stored in tmpfs with symlink from inbox
- [ ] Deleting the progress file still cancels the transfer
- [ ] Transfer resumes and recreates progress file after reboot
- [ ] Sender's `transfers` file symlinked to `/tmp/rmail-transfers`

### Consent form regeneration bug (#346)
- [ ] Consent form file is removed from inbox after the attachment it gated is delivered
- [ ] Consent form file is removed from inbox after the recipient declines it
- [ ] Sending a second attachment creates its own consent form (not a rewrite of the first)
- [ ] Second consent form shows the correct sender/filename/metadata for its own file
- [ ] User edits to a consent form (e.g. deleting `deny`) are not overwritten by a later sync
- [ ] Mid-transfer cancel by writing "deny" into the progress file works
- [ ] Mid-transfer cancel by deleting the progress file works
- [ ] Progress file is removed from inbox after a mid-transfer cancel
- [ ] Chunk arriving with an unknown `attachment_id` is rejected with 404
- [ ] Filename path separators in an attachment request are sanitized (no traversal)
- [ ] Per-chunk filename/subject fields are ignored; the request-time sanitized filename is used throughout

## 6. Sync and networking

### Batch sync per contact (#324)
- [ ] Connection pre-check before running operations for each contact
- [ ] Failed connection → all ops skipped, single log line (not N separate failures)
- [ ] Successful connection → all pending ops run sequentially over same connection
- [ ] Different contacts processed in parallel (coroutines)

### LAN discovery (#102, #203)
- [ ] UDP LAN discovery finds peers on same network
- [ ] LAN discovery includes LAN IP in payload, multicast + subnet scan fallback

### DNS hostnames in contacts (#311)
- [ ] Contact with hostname in `.ip` field resolves and connects outbound
- [ ] Inbound connection from hostname contact: resolve and match against connecting IP
- [ ] Hostname resolution cached ~5 minutes
- [ ] LAN peer cache resolves hostnames before comparing IPs

### Multiple IPs per contact (#347)

**Phase 1 (shipped):**
- [ ] `load_contacts` collects every `name.ip = …` line into `contact.ips` (list); `contact.ip` is set to the first entry
- [ ] Legacy `name.ipv6 = …` is folded into `contact.ips` (appears in `contact_hosts()` output)
- [ ] `align_contacts` groups scattered lines for the same contact at the contact's first position
- [ ] `align_contacts` preserves non-contact lines (comments, blanks, section headers) in place
- [ ] Multi-IP contact receives an inbound `/update-address`: list is **not** overwritten; port still updates
- [ ] Single-IP contact's update-address flow still rewrites `.ip` as before
- [ ] `contact_hosts()` returns at least one entry for any contact with an IP; empty list otherwise
- [ ] Single `ip` field accepts IPv4, IPv6, and DNS hostname — type detected automatically

**Phase 2 (shipped):**
- [ ] Healthy first address: `http_post_batch_with_fallback` dispatches in parallel and returns first-attempt results (no serial regression)
- [ ] First address unreachable, second reachable: retry picks up and returns the second address's result as the entry's final result
- [ ] HTTP-level error (e.g. 404) from first address: no fallback attempted; first-address result returned as-is
- [ ] All addresses unreachable: final result reports failure (no ok, no status)
- [ ] `sync_outbox`, `sync_inbox`, consent-response, attachment-cancel, attachment-chunk, and update-address paths all use the fallback wrapper

**Phase 3 (shipped):**
- [ ] Fallback win for a non-first address moves that address to the top of the contact's `ip` block on disk
- [ ] `promote_contact_address` is a no-op when the winner is already first, the contact has fewer than two addresses, the address isn't in the list, or the resulting file text would be unchanged
- [ ] Non-`ip` fields (port, token, etc.) stay at their original positions after promotion
- [ ] Subsequent sync cycles after a promotion hit the new first address directly (no more fallback walk)
- [ ] A malformed contacts file during promotion doesn't crash the sync cycle (pcall guard)

### Per-IP ports (#354)
- [ ] `alice.ip = 192.168.1.5:22` resolves to addr `192.168.1.5`, port `22`
- [ ] `alice.ip = alice.duckdns.org:8025` resolves to addr `alice.duckdns.org`, port `8025`
- [ ] `alice.ip = [2001:db8::1]:8025` resolves to addr `2001:db8::1`, port `8025`
- [ ] `alice.ip = [2001:db8::1]` resolves to addr `2001:db8::1`, port inherited from `alice.port`
- [ ] `alice.ip = 2001:db8::1` (bare IPv6, multi-colon) inherits port without trying to split
- [ ] `alice.ip = 192.168.1.5` inherits port from `alice.port`
- [ ] `contact.endpoints` preserves the raw line value for each entry (so promote can match it verbatim)
- [ ] All six batch call sites send via `endpoints = contact_endpoints(c)`
- [ ] Retry fallback uses the per-endpoint port, not a shared port
- [ ] Promote preserves `HOST:PORT` syntax on the reordered line (no silent rewrite to bare HOST)

### IPv6 (#304)
- [ ] IPv6 connections accepted alongside IPv4

### Port forwarding (#302)
- [ ] Port forwarding uses correct LAN IP

### IP recovery (#300)
- [ ] IP recovery works after simultaneous IP change

### Stale contacts after IP change (#312)
- [ ] (Design phase — no tests yet)

### Simultaneous IP change (#313)
- [ ] (Design phase — no tests yet)

## 7. Android — connection and sync

### Sync behavior
- [ ] `saveOutboxFile()` triggers immediate sync
- [ ] Error banner persists during sync, clears only on success (#305)

### Error display (#317)
- [ ] "Failed to connect" error stays visible during sync attempt
- [ ] Error clears only when sync succeeds

### "Read timed out" (#320)
- [ ] Root cause identified (server delay, network, or client timeout)
- [ ] Timeout value adjusted or error message softened

### Security (#314)
- [ ] Only rmail app code can write to outbox and trigger sync
- [ ] No filesystem watcher that external apps could feed files into

## 8. Android — composing messages

### Duplicate filename prevention (#315, Android side)
- [ ] Cannot save outbox file whose converted filename matches existing outbox file

### Cursor-aware scrolling (#316)
- [ ] Cursor off-screen → view scrolls so cursor is 3 lines above keyboard
- [ ] Continued typing doesn't scroll until cursor reaches last visible line
- [ ] At last visible line, scrolls proportionally so line becomes third-from-bottom
- [ ] Deleting from third line reverses scroll in same increments
- [ ] Manual scroll resets the zone; typing resumes from new position
- [ ] Typing below keyboard scrolls by ~3 lines, not 1

### Sending progress animation (#322)
- [ ] Green notification bar slides in with "sending..." after send
- [ ] Dot progress bar counts down to sync (1 dot/sec, 30 dots)
- [ ] Dots disappear randomly, last 3 disappear last
- [ ] Final 3 seconds: last 3 dots slide off right edge
- [ ] Text becomes "sent" (delivered) or "ready" (offline/unreachable)

## 9. Android — reading and editing outbox messages

### Outbox edit redesign (#321)
- [ ] Tapping outbox message opens for reading
- [ ] Tapping cursor position switches to compose with to/attachments/subject filled in
- [ ] "Send" becomes "Save" in edit mode
- [ ] Back button asks "save changes?" — "no" discards
- [ ] Removing `to:` line marks recipient for deletion on their side
- [ ] Adding `to:` line sends as new to new recipient, update to existing

### Update button (#321)
- [ ] Update button shows only zipping/transfer progress
- [ ] Button hidden when nothing is in progress

## 10. Android — reading inbox messages

### 80-character monospace scaling (#318)
- [ ] Inbox message view uses monospace font scaled to 80 characters wide
- [ ] +/- control adjusts width in increments of 20 (60, 80, 100, 120)
- [ ] Width preference persists across sessions

### Orphan + button (#319)
- [ ] + button either has a clear function or is removed

## 11. Android — contacts and settings

### DNS hostnames (#311, Android side)
- [ ] Setup screen accepts hostnames in IP field
- [ ] Contacts editor accepts hostnames

## 12. Install script

### Interactive prompts
- [ ] Arrow keys move the cursor instead of inserting control characters (#333)
- [ ] Every prompt can be supplied via CLI flag or env var; supplied values skip the prompt silently (#334)
- [ ] On re-run, existing config values show as the default in `[ ]` brackets (#343)

### Environment reporting
- [ ] Displayed Lua version matches the actual interpreter found, not a hardcoded string (#335)
- [ ] `zip` / `unzip` detected on Arch Linux when installed; install hint shown otherwise (#337)

### Firewall and copy
- [ ] Firewall section explains what a port is and shows how to list open ports per-platform (#336)
- [ ] "(recommended for reproducibility)" line removed from install output (#336)
- [ ] "AES-256-GCM encryption is active - no configuration needed" line removed (#341)
- [ ] Name prompt no longer claims the value is shown to contacts (#338)

### Portability
- [ ] Installer runs from a read-only/USB mount without writing to its own directory (#339)
- [ ] Cross-platform entry points exist for Linux, macOS, and Windows/WSL (#339)

### Config writing
- [ ] Config file written as soon as required fields are collected (name, port, mail dir, …) (#340)
- [ ] Mail-directory option is present and correct in the generated config (#343)
- [ ] Re-running install with existing config: `mail` value appears as the `[bracket]` default (#343)
- [ ] `set_config_value` appends a missing key and replaces a present one without touching other lines (#343)
- [ ] `set_config_value` preserves comments and commented-out `# key = …` lines (#343)
- [ ] Paths containing `|`, `\`, or `&` round-trip through both the config update and the docs-template expansion without mangling (#344)
- [ ] Config filename is `~/.config/rmail/config-<slug>` where slug is the mail path with `/` → `-` (intentional, not a bug) (#344)

### Service files point at the config, not the mailbox
- [ ] Generated systemd/runit/openrc/NixOS service files pass the config path (not the mail dir) to rmail.lua
- [ ] `rmail.lua <config-file>` starts the daemon using `mail = …` from the config
- [ ] `rmail.lua <mail-dir>` still works (backwards compat for existing service files)
- [ ] Error surfaced when config path is passed but the config has no `mail` line

### Dependencies
- [ ] Installer prompts before installing project-local luasocket (#342)
- [ ] System Lua + project-local luasocket: `LUA_PATH`/`LUA_CPATH` lets `require("socket")` resolve (#342)

### Readability
- [ ] Install script reads as plain, linear programming — not dense shell idioms (#345)

## 13. Future / design phase

These have no test cases yet. Listed here so they aren't forgotten.

- [ ] #301 — Monitor program (design phase)
- [ ] #308 — Synced phone config (design phase)
- [ ] #309 — Android script editor (depends on #308)
- [ ] #310 — Periodics (depends on #308)
- [ ] #329 — Thin client desktop viewer (design phase)
