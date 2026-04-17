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
- [ ] Daemon: same sender sends two messages with the same converted subject → each lands in inbox as a distinct file (second gets a `-<short-id>` suffix)
- [ ] Daemon: different senders with the same subject → older `-from-<sender>` disambiguation still applies
- [ ] Daemon: re-delivery of the *same* message_id (e.g. attachment-followup path) still merges into the existing inbox entry, no suffix added
- [ ] Duplicate check uses converted filename (after spaces-to-dashes), not raw subject
- [ ] Android: sending "hello world" when outbox has "hello-world" triggers the "Subject already in outbox" dialog
- [ ] Dialog's Cancel preserves the draft intact
- [ ] Dialog's Replace overwrites the existing outbox file deliberately

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

### Outbox header robustness (#363)
- [ ] Blank line between `to:` and `attach:` does NOT terminate the header — attach still recognized, attachment gets queued
- [ ] Whitespace-only line (spaces/tabs, no content) between header lines treated the same as a truly blank line
- [ ] Multiple blank lines between header items still allowed
- [ ] First non-blank, non-header line still correctly ends the header block (body unchanged)
- [ ] File with only headers + blank lines (no body) parses as body = ""
- [ ] `remove_recipient_from_file` and `remove_attach_from_file` use the same blank-tolerant scanning rule — no orphan `attach:` lines left behind after a to: is removed
- [ ] `attach:` path pointing to a non-existent file: daemon logs `attach: file not found: <path>` with the outbox filename, and inserts a `// MISSING ATTACHMENT:` marker line below the offending attach
- [ ] Marker not duplicated on subsequent sync cycles (same `attach:` line, same missing file → one marker)
- [ ] User fixing the path (making the file exist) lets the attachment proceed on the next sync cycle; stale `//` marker stays in the file until the user removes it
- [ ] The fix does NOT reformat or remove blank lines the user intentionally put in their outbox file — file-on-disk only changes when glob expansion (#362) or a #363 marker needs to be written

### `attach:` glob expansion (#362)
- [ ] `attach: ~/photos/*.jpg` in an outbox file is rewritten in place to one `attach:` line per matching file, absolute paths, sorted
- [ ] `*` matches only regular files — directories and dotfiles in the glob dir are skipped
- [ ] `?` and `[...]` character classes work (e.g. `app-[0-9][0-9].log`, `report-0?.pdf`)
- [ ] Zero-match glob: line is left unchanged in the file, warning logged once per session (no spam on subsequent sync cycles)
- [ ] Glob in directory component (e.g. `~/p*/file.jpg`): warning logged, line unchanged
- [ ] Relative glob (no leading `/` or `~`): warning logged, line unchanged
- [ ] Non-glob paths (no `*`, `?`, `[`) are untouched — no rewrite happens if a file only has literal attach: lines
- [ ] After glob expansion, the normal attachment pipeline completes (consent form, chunk transfer, etc.) for each expanded file
- [ ] When a transfer completes, `remove_attach_from_file` strips the specific expanded line, not the original glob (because the glob line no longer exists in the file)
- [ ] Re-parsing an already-expanded file (with no globs left) produces no log output and no file write

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
- [ ] Receiver's inbox stub text reads "delivered as attachment at <paths.attachments>/<subject>" with the receiver's own resolved path
- [ ] Old daemons that ignore `auto_body` still see the sender's fallback stub text

### list_files skips directories (#356)
- [ ] `list_files` on a dir containing files + subdirs returns only files
- [ ] Delete an inbox file and create a directory with the same name before next sync: sync_inbox still notifies the sender of the deletion
- [ ] Consent/progress file overlaid by a same-named directory: handler treats the transfer as cancelled (expected)
- [ ] Android attachments API doesn't surface subdirs as attachments
- [ ] Directory in a watched dir logs a one-line warning the first time it's encountered; subsequent cycles stay silent until daemon restart
- [ ] Outbox-dir warning tells the user how to send the directory as an attachment (provides an `attach: <path>` hint)
- [ ] Inbox-dir warning makes clear the daemon didn't create the directory
- [ ] Attachments-dir warning is generic (user-organised subfolders are legitimate)

### Attachments survive inbox-message deletion (#355)
- [ ] Sender-initiated delete: inbox file removed, attachments in paths.attachments untouched
- [ ] User-local delete (sync_inbox detects missing file): attachments untouched, sender still gets /delete notification
- [ ] Self-delete (`self_delete_from_inbox`): attachments untouched
- [ ] Android `/api/inbox/delete` from phone: attachments untouched
- [ ] `on_delete` hook still fires on every delete path

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

### Per-IP ports (#347 Phase 4)
- [ ] `alice.ip[1] = 192.168.1.5` + `alice.port[1] = 22` creates endpoint with addr `192.168.1.5`, port `22`
- [ ] `alice.ip[2] = host.example.com` without `alice.port[2]` inherits `alice.port`
- [ ] Default `alice.ip` + `alice.port` (unindexed) is always the first endpoint tried
- [ ] Default endpoint is immune to promotion reordering
- [ ] Old-style config with multiple unindexed `name.ip` lines: first becomes default, rest auto-indexed
- [ ] Old-style promotion (`promote_contact_address`) still works for auto-indexed entries
- [ ] `promote_contact_index` rotates both `ip[N]` and `port[N]` values together
- [ ] Promotion renumbers indices to be contiguous starting at 1
- [ ] Orphan `port[N]` with matching `ip[N]` missing and no default ip: logged warning, endpoint skipped
- [ ] Endpoint with no port (no `port[N]`, no default `port`): logged warning
- [ ] All batch call sites send via `endpoints = contact_endpoints(c)`
- [ ] Retry fallback uses the per-endpoint port, not a shared port

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

### Error display (#317) — verified by code inspection
- [x] "Failed to connect" error stays visible during sync attempt (no code path clears `_syncError` on sync start)
- [x] Error clears only when sync succeeds (one of two explicit clears: success branch + mailbox switch)

### "Read timed out" (#320)
- [x] Root cause identified (10 s socket timeout too aggressive for a busy sync)
- [x] Timeout raised to 30 s
- [ ] Error message softened — timeout now shows "server didn't respond in time — will retry" on the red box instead of "Read timed out"
- [ ] ConnectException shows "server not reachable — will retry"
- [ ] UnknownHostException shows "server host couldn't be resolved"
- [ ] Decryption failure shows a token-hint message
- [ ] Unrecognised errors still surface the raw message (no silent swallowing)

### Security (#314)
- [ ] Only rmail app code can write to outbox and trigger sync
- [ ] No filesystem watcher that external apps could feed files into

## 8. Android — composing messages

### Duplicate filename prevention (#315, Android side)
- [ ] Cannot save outbox file whose converted filename matches existing outbox file

### Cursor-aware scrolling (#316 — closed 2026-04-14, second pass)
**Shipped floor:**
- [ ] Typing in the compose body keeps the cursor visible above the keyboard through many wraps in a row
- [ ] After each wrap, the new line is fully visible (not half-clipped by the keyboard)
- [ ] Caret lands roughly 3 lines above the keyboard, not right at the edge
- [ ] Continued typing doesn't scroll until cursor reaches the last visible line
- [ ] Tapping inside the body to reposition the cursor scrolls the view to bring that cursor location into view
- [ ] Forward / Reply prefilled bodies still place the cursor sensibly (end of text)

**Parked (revisit if feel warrants):**
- Per-character proportional scroll across the bottom line (horizontal drift)
- Delete reverses the per-character scroll in the same increments
- Manual scroll resets the zone; typing resumes from new position

### Sending progress animation (#322)
- [ ] Green bar appears at the top of the Inbox panel after Send
- [ ] Text starts as "sending…", 15 white dots visible
- [ ] Dots disappear in random order from the left 12 positions (~5/sec)
- [ ] Rightmost 3 dots stay lit during the countdown
- [ ] When sync finishes successfully, the last 3 dots slide off the right edge (not fade)
- [ ] Text changes to "sent" at the end of a successful send
- [ ] "sent" auto-dismisses after ~1.5 s
- [ ] When sync fails (daemon unreachable), text changes to "ready" and the bar persists
- [ ] Repeat send: new animation replaces the previous one cleanly

## 9. Android — reading and editing outbox messages

### Outbox edit redesign (#321)
**Shipped:**
- [ ] Tapping an outbox message opens it for reading (unchanged)
- [ ] An Edit (pencil) icon in the top-bar opens the composer with `to:` lines, body, and existing `attach:` lines preserved
- [ ] In edit mode, the top-right action shows a checkmark (Save), not the send arrow
- [ ] Saving overwrites the existing outbox file (no new filename, no duplicate-subject prompt)
- [ ] No green sending-progress animation appears for an edit (the daemon's update path handles delivery)
- [ ] Android back gesture while dirty → "Save changes?" dialog (Discard / Keep editing)
- [ ] Tapping the underlined mailbox-name title while dirty → same dialog
- [ ] Daemon already handles to:-line additions/removals via living-messages diff; no Android work needed

**Deferred:**
- [ ] Tap-anywhere-on-body to start editing at that cursor position (today: explicit Edit button)
- [ ] Visible attach-line management in edit mode (today: invisible-but-preserved)
- [ ] Update progress indicator at the position of the old Update button

## 10. Android — reading inbox messages

### 80-character monospace scaling (#318)
- [ ] Inbox message view uses monospace font scaled so 80 chars exactly fill the screen width (default)
- [ ] `+` button in the top bar widens by 20 cols (80 → 100 → 120…); shrinks the rendered text
- [ ] `–` button narrows by 20 cols (80 → 60 → 40…); enlarges the rendered text
- [ ] Width preference persists across app restarts
- [ ] +/- buttons hidden on outbox messages and consent files (only shown on regular inbox messages)

### Delete mailbox (#357)
- [ ] Settings panel shows a "Danger zone" section with a red "Delete mailbox" button
- [ ] Tapping it opens a confirmation dialog
- [ ] Dialog says the deletion is local-only and doesn't touch the home server
- [ ] If everything is in sync, dialog shows "Your mailbox files are safe on the home server"
- [ ] If the outbox has unsynced files, dialog lists them as "outbox/<filename>"
- [ ] Confirm removes the mailbox from the registry, deletes the on-device mailbox directory, and navigates back to the mailbox list
- [ ] Cancel leaves everything unchanged

### Reply / Forward (#358)
- [ ] Opening an inbox message and tapping Reply switches to the Write panel with recipient = sender, subject = "Re: <original>", body = quoted original
- [ ] Opening the overflow menu and tapping Forward switches to Write with recipient = empty, subject = "Fwd: <original>", body = quoted original
- [ ] Re-forwarding a "Fwd: foo" message still yields "Fwd: foo" (no stacking)
- [ ] Re-replying to a "Re: foo" message still yields "Re: foo"
- [ ] Forward from the outbox-read screen works identically (recipient empty, Fwd: subject, quoted body)
- [ ] Reply on the outbox-read screen is a no-op (no own-message replies)

### Tappable mailbox title (#359)
- [ ] Top-level mailbox view has no "←" arrow in the top-left
- [ ] The mailbox name (title) is underlined and tappable, jumping to the mailbox list
- [ ] Inside the contact editor sub-view, the "←" arrow still appears and returns to the contacts panel

### Orphan + button (#319)
- [ ] Write panel's top-bar no longer has a "+" button (only Send)
- [ ] Outbox panel's "+" still jumps to the Write panel
- [ ] Contacts panel's "+" still opens the contact editor
- [ ] Files panel's "+" still opens the file picker via Write panel
- [ ] Contact-editor in-body "+" still adds a custom field row
- [ ] Composer in-body "+" still adds a recipient and "+" still attaches a file
- [ ] Mailbox list "+" still adds a new mailbox

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
