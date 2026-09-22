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

### Per-contact sync timers (#377) — implemented 2026-09-22

Settings as built: floor **30s**, additive **+360s** per failed cycle, **2h**
ceiling, **±30s** jitter on every due time. No TTL — a permanently-failing op
is backed off, never dropped. The "startup ping" is an `/update-address`
announce ("hi, I'm still here, at this location"), reusing the existing
pending-address path rather than a new endpoint.

Verified at scaled constants (floor 2s, step 3s, ceiling 20s) against two
RFC 5737 TEST-NET addresses and a live loopback peer pair:

- [x] On daemon start, every contact is contacted once (startup ping)
      — `startup: announcing <ip>:<port> to 2 contact(s)`, delivered
- [x] Each contact has an independent timer — two contacts that failed in the
      same cycle drifted apart and stayed apart, confirming jitter decouples
      them rather than keeping them in lockstep
- [x] An unreachable contact backs off progressively — observed
      2→5→8→11→14→17→20s and then silent at the ceiling
- [x] Backoff settles at the ceiling and stops growing (no lines above it)
- [x] An inbound request from a contact resets that contact's timer — peer
      came up at 17s backoff, next retry was at the floor
- [x] A withheld op is not reported as "unreachable" (only contacts with a
      real attempt reach the summary)
- [ ] Backoff resets to the floor after a *successful outbound* exchange
      (inbound reset verified; success path not yet exercised end-to-end)
- [ ] Inbound resets **only that contact's** timer, others unchanged —
      needs a 3-contact run; only a single-contact case was tested
- [ ] A reply to an inbound message goes out promptly rather than waiting for
      the backoff delay (implied by the reset, not directly measured)
- [ ] Deleting an unreachable contact stops its retries entirely
- [ ] Verify at **production** constants over a multi-hour run that a dead
      contact settles at the 2h ceiling (~12 attempts/day, down from ~5,700)
- [ ] A contact with no queued ops does not spin the main loop (op-less
      contacts are swept back to the floor; confirm no busy-wait)

### Address-set announcement (#388) — phase 1 implemented 2026-09-22

- [x] A contact holding a private address for us keeps it as the pinned
      default and gains our public/LAN addresses as `ip[N]`
- [x] Announcing an unchanged set rewrites nothing (no contacts-file write,
      no inotify storm, no notice)
- [x] Notice is written as a dotfile `.address-update-<name>`
- [x] Notice is retired by a successful *outbound* exchange with that
      contact, not by receiving from them
- [x] An idle pair still retires the notice (it queues an announcement of
      our own as the verifying traffic)
- [x] Normal delivery unaffected: 6 queued files still go out in one batch
      in the same second
- [ ] Hostnames survive an address-set announcement (logic present, not yet
      exercised end to end)
- [ ] A peer that predates #388 (sends `ip`/`port`, no `ips`) still works
      via the single-address fallback
- [ ] IPv6 addresses round-trip through the set correctly
- [x] `name.local-ip` / `local-ip[N]` parsed; a public value is ignored
      with a warning
- [x] Local addresses are tried first only when they share our /24; a
      different-/24 local address is not tried at all
- [x] Announcement carries local addresses only to a contact on our LAN
- [x] Received private address from another /24 is dropped, not stored
- [x] Received local set replaces the sender's `local-ip` lines; re-sending
      the same set rewrites nothing and writes no notice
- [x] Canonical contacts form carries `ip[N]`/`port[N]`/`local-ip` and
      round-trips to an identical hash
- [ ] Phone contact edit no longer deletes `ip[N]` / `local-ip` lines on
      the server (end to end)
- [ ] Android settings: add/remove server and local addresses; private
      address in the server list refused on save; old single-host config
      with a LAN host shows it under local addresses
- [ ] Android at home connects via local address; on mobile data skips it
      without delay (re-probed at the start of each sync cycle)
- [ ] `.address-update-*` marker written on a real change even when the
      sender sends `notify = false`, and removed after the next successful
      send to that contact (no user action)
- [ ] ~~`.address-update-*` notices do not sync to Android~~ — by design
      now: the marker is bookkeeping, not a notification
- [ ] Android: other calls between syncs reuse the address the last sync
      picked; a failed sync forgets it

### Public IP recheck every 36h ±12h (#379) — implemented 2026-09-22

Changed from the originally-filed "once per day": the delay is drawn
uniformly from **[24h, 48h)**, redrawn after every check. A wider-than-a-day
window means it cannot land in the same part of the clock twice running, and
a 36h mean is not a divisor of 24h so the check precesses through the day.
All three startup-only checks moved onto the timer, not just public IPv4.

- [x] Public IP is re-checked with no daemon restart (verified at a scaled
      6s ±2s interval; fires repeatedly at correctly-varying gaps)
- [x] Delay distribution is correct — 20,000 draws gave
      `min=24.00h max=48.00h mean=36.00h`
- [x] Restarting the daemon does not reproduce the same "random" time.
      The root cause is fixed: `math.randomseed` was never called, so
      unseeded LuaJIT returned `794207` from three separate processes;
      seeded from `/dev/urandom` it returns different values each time
- [x] The generator is also reseeded on every check, so a months-long
      process does not ride one boot-time seed for its whole life
- [x] The routine probe queries only one provider — `check_public_ip`
      returns on the first provider that answers (this was already true)
- [x] A real IP change mid-run is detected and confirmed — the live daemon
      logged `public IP changed: 184.3.192.218 -> 97.120.253.166 (confirmed)`
      and queued notifications, which was the outage that motivated the issue
- [x] `detect_ip_change` now distinguishes "no answer" from "no change"
      (returns false vs true), so a failed probe cannot read as "unchanged"
- [ ] A failed probe retries in 1h rather than waiting the full window —
      implemented, but not yet exercised by fault injection (block DNS)
- [ ] `detect_ipv6_change` and `check_lan_ip_change` fire on the timer too
      (wired, but neither has been observed changing mid-run)
- [ ] Confirm over several days that the check time visibly precesses

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

### Export mailbox (#378)
- [ ] "Export mailbox" appears in mailbox settings near "Delete mailbox",
      and is **outside** the red Danger zone (export is not destructive)
- [ ] The mailbox picker's three-dot dialog shows "Export" on the left,
      opposite "Close"
- [ ] Export screen lists inbox and outbox messages with individual checkboxes
- [ ] Select all / none works both per folder and globally
- [ ] Only the selected messages are written — unselected ones are not
- [ ] Destination is chosen via the system picker, with no storage
      permission prompt
- [ ] Exported files are visible in a file browser and can be opened by
      another app
- [ ] Exported message mtimes match the original authoring time (#374),
      not the time of export
- [ ] Export acts on the chosen mailbox only, never all mailboxes at once
- [ ] Mail still lives in private `filesDir` after an export — export copies,
      it does not relocate the store

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
Most of this section is covered by `scripts/test-mailbox-selection.sh`;
the first item is not, because it inspects what the installer generates.
- [ ] Generated systemd/runit/openrc/NixOS service files pass the config path (not the mail dir) to rmail.lua
- [ ] `rmail.lua <config-file>` starts the daemon using `mail = …` from the config
- [ ] `rmail.lua <mail-dir>` is refused with a usage error naming the config form (#381)
- [ ] A config planted at the old `~/.config/rmail/config-<slug>` path is not found from a directory argument (#381)
- [ ] A relative `mail = .` resolves against the config file's own directory, not the working directory (#381)
- [ ] Error surfaced when config path is passed but the config has no `mail` line

### The mailbox holds its own config, hooks and program (#382)
The daemon-side rows are covered by `scripts/test-mailbox-selection.sh`.
The installer and migration rows are not — they need a real run.
- [ ] A fresh install writes the config to `<mailbox>/config` as a real file, not a symlink, and creates no `~/.config/rmail/` (#382)
- [ ] The mailbox served is the directory the config sits in; there is no `mail =` key in a newly generated config (#382)
- [ ] A leftover `mail =` line from the old layout is ignored rather than obeyed, even when it names a different directory (#382)
- [ ] A fresh install puts the six hook scripts in `<mailbox>/hooks/` and the config references them as `./hooks/<name>.sh` (#382)
- [ ] Editing one mailbox's hook does not change another mailbox's behaviour, and does not modify the checkout (#382)
- [ ] Relative hook paths resolve against the config's directory, not the working directory — verify by starting a daemon from an unrelated directory and confirming the hook fires (#382)
- [ ] Re-running the installer on an existing mailbox leaves edited hooks alone and reports how many it kept (#382)
- [ ] A fresh install puts NO program copy in the mailbox — no `program-files/`, and the service runs the checkout's `rmail.lua` (#382)
- [ ] Generated service files for all five init systems run the checkout's `rmail.lua` with the mailbox's config as the argument (#382)
- [ ] A mailbox keeps working after the checkout it was installed from is renamed or deleted (#382)
- [ ] The installer no longer reads other mailboxes' configs for anything — verify with a second install while the first mailbox is unreadable (#382)
- [ ] The port prompt warns when something is already listening on the chosen port, including a non-rmail program (#382)
- [ ] With neither `ss` nor `netstat` installed, the port check says it could not run rather than passing silently (#382)
- [ ] ~~IP-change notices default to off in a newly generated config (#382)~~ — setting removed (#388): changes are always announced and applied
- [ ] `migrate-mailbox-layout.sh --dry-run` reports every change and writes nothing (#382)
- [ ] Migration is idempotent: a second run keeps existing hooks, removes nothing twice, and refreshes only the program files (#382)
- [ ] Migration leaves inbox, outbox, contacts, attachments and `.state/` untouched — compare file counts before and after (#382)
- [ ] Migration warns when the old `mail =` line names a directory other than the mailbox being migrated (#382)
- [ ] A portable drive generated after this change has the same mailbox layout as an installed one, with hooks in `hooks/` (#382)
- [ ] The generated drive config contains no mount-point path anywhere, and the drive runs from a different mount point than it was made on (#382)
- [ ] `validate-router-settings.sh` and `generate-docs.sh` both take a mailbox and neither reads `~/.config/rmail/` (#382)
- [ ] Generated configs contain no shell-substitution damage — grep a fresh config for backtick artefacts, since the heredoc that writes it expands them (#382)
- [ ] A generated drive carries only the allowlist: daemon, launcher, `deps/lua`, `libs/`, the two `.c` files, `BUILD-NOTES.txt`, `LICENSE`. No `install.sh`, no `scripts/hooks/`, no Android client, no docs, no transcripts (#382)
- [ ] `make-mailbox-drive.sh` refuses to build a drive when the checkout has no compiled Lua at `deps/lua/bin/lua` (#382)
- [ ] The generator verifies before finishing that the copied Lua loads the copied libraries, and refuses if not (#382)
- [ ] The generator warns when the bundled Lua links readline, naming `install.sh --force` as the fix (#382)
- [ ] After a Lua rebuild, `ldd deps/lua/bin/lua` shows only libc and libm — no readline, no ncurses (#382)
- [ ] A running drive daemon uses the drive's own interpreter — check with `pgrep -af rmail.lua` that the path is a temporary copy (`$XDG_RUNTIME_DIR/rmail-*/deps/lua/bin/lua`) of the drive's, not a system lua (#382, #388)
- [ ] Plugging a drive in announces nothing; only running a launcher does (#388)
- [ ] `sync-with-contacts.sh` announces, sends the outbox, stays reachable 60s (or the given seconds), exits 0, and removes its temporary copy (#388)
- [ ] `sync-with-contacts.sh abc` prints usage and exits 2 (#388)
- [ ] `auto-sync.sh` runs until the drive is pulled, then exits cleanly ("mailbox ... is gone") and removes its temporary copy (#388) — verified with a simulated unplug; not yet with a real USB pull
- [ ] Mail from a contact arrives within a `sync-with-contacts.sh` window after they had backed off (the announcement resets their timer) (#388)
- [ ] A drive whose libraries cannot load stops with the architecture message, naming both the drive's and the host's, and does NOT try to recompile (#382)
- [ ] `BUILD-NOTES.txt` names the two `cc` commands and the `make linux` that built what ships (#382)
- [ ] A drive's `rmail_crypto.so` needs no `libcrypto` from the host — `ldd` shows libc only (#382)
- [ ] The generator refuses to build a drive when no `libcrypto.a` can be found (#382)
- [ ] A drive daemon logs "AES-256-GCM encryption enabled" and completes a send, proving the static crypto works and not merely links (#382)
- [ ] A drive carries no `liblua.a`, no `luac`, and no Lua man pages — none are used at runtime (#382)

### Recipients the daemon cannot resolve
Also covered by `scripts/test-mailbox-selection.sh`.
- [ ] A `to:` name that is both your own identity and a contact is refused, logged naming both readings, and marked `// AMBIGUOUS RECIPIENT` in the outbox file (#381)
- [ ] That message stays in the outbox undelivered, and nothing appears in your own inbox (#381)
- [ ] A `to:` name that is your own identity and *not* a contact still self-delivers to your inbox (#381)
- [ ] A message to an unknown contact keeps its `// UNKNOWN CONTACT` marker and is not deleted by the outbox cleanup sweep (#381)
- [ ] A `to:` line that is the last line of a file, with no trailing newline, gets its marker on a line of its own (#381)

### Dependencies
- [ ] Installer prompts before installing project-local luasocket (#342)
- [ ] System Lua + project-local luasocket: `LUA_PATH`/`LUA_CPATH` lets `require("socket")` resolve (#342)

### Readability
- [ ] Install script reads as plain, linear programming — not dense shell idioms (#345)

## 12b. State files are plaintext (#348 reversed)

All PII-hashing from #348 steps 1–6 has been reverted; state files
should be fully plaintext mirrors of contacts/inbox/outbox.

- [ ] `cat .state/inbox.json` shows `"from": "<name>"` with plaintext contact names, no 64-hex hashes
- [ ] `cat .state/outbox.json` shows plaintext recipient names as the `.recipients` keys; entries contain `.message_id` but no `.token` or `.token_hash`
- [ ] `cat .state/chunks-outgoing.json` shows plaintext `.to` (recipient name), `.original_path`, `.filename`, `.outbox_file`, AND `.compressed_path` — no `.zip_id` field; paths are greppable
- [ ] `cat .state/consent-pending.json` shows plaintext `.from`; `cat .state/consent-responses.json` shows plaintext `.to`
- [ ] `cat .state/nat_security_warned.json` is keyed by plaintext contact names (truthy values only)
- [ ] `cat .state/pending-address.json` is keyed by plaintext contact names
- [ ] Loading legacy `.state/` files written by pre-revert code still works: hashed `.to`/`.from` fields stay as hash strings in memory (no crash) and get rewritten to plaintext on the next save; hashed top-level keys in `nat_security_warned.json` / `pending-address.json` are resolved to plaintext or dropped on load via `unmigrate_hashed_keys`
- [ ] Renaming a contact while outbox messages are in-flight produces an `unknown contact <name>` log line for the stale recipient (no auto-rename detection); documented recovery is `sed -i 's/"<old>"/"<new>"/g' .state/*.json`
- [ ] After rename + sed fix, body edits (#306) propagate correctly to the renamed recipient on the next sync
- [ ] No code path anywhere calls `hash_contact_name` except the `unmigrate_hashed_keys` legacy-state resolver
- [ ] `hex_sha256` remains in use only by `canonical_contacts_hash` (protocol-level contacts digest) and `hash_contact_name` (legacy-state resolver)

## 13. Future / design phase

These have no test cases yet. Listed here so they aren't forgotten.

- [ ] #301 — Monitor program (design phase)
- [ ] #308 — Synced phone config (design phase)
- [ ] #309 — Android script editor (depends on #308)
- [ ] #310 — Periodics (depends on #308)
- [ ] #329 — Thin client desktop viewer (design phase)

### Attachment pipeline audit (#391) — implemented 2026-09-22

- [x] New-recipient body held while an `attach:` path is missing; marker written, cleared once the file exists
- [x] Held outbox file is not deleted by the "no recipients left" cleanup
- [x] Consent form recorded in `inbox.json` and offered to the phone by `/api/sync`
- [x] Phone deleting a consent form declines it and sends no /delete to the sender
- [x] `remove_consent_form` drops the form's `inbox.json` entry
- [x] Consent response to an unknown (hashed) contact is dropped with a log line
- [x] Failed/skipped attachment request keeps the transfer and zip; next cycle re-asks with the same zip
- [x] Phone: stuck attachment shows an error under the message in the outbox list (seen on device)
- [x] Phone: sync state records outbox hashes; held files are skipped
- [ ] Phone: send a photo → "preparing / zipping / uploading" under the message, then the message goes out with a consent form arriving at the recipient
- [ ] Phone: kill the app mid-upload, reopen → upload resumes from the staged copy and completes
- [ ] Phone: consent form appears in the phone inbox; Accept → transfer starts; Deny → form disappears on both sides
- [ ] Phone: editing an already-sent outbox message on the phone reaches the recipient as an update
- [ ] Share-sheet attachment (from Gallery) arrives as an attachment, not a missing file
- [ ] Response to a transfer the sender no longer has → sender 404 → receiver clears the form
- [ ] July victory-garden.jpg accept resolves to kuvalu and is sent or cleared (check log after restart)
- [x] Phone upload is stored unzipped in `attachments/` under its own name; identical re-upload reuses it; different content becomes `name-2.ext`; `.uploads/` left empty (harness)
- [ ] Files tab `+` → file shows "waiting to upload", then "Present on: <server>, android" after sync; no consent form anywhere
- [ ] Attachment sent from Write appears in Files, and the recipient receives the real file (not a zip)
- [ ] Adding a file whose name exists on the server with different content → stored as `name-2.ext` on both sides
- [x] Received attachment with a name already in `attachments/` is saved as `name-2.ext`; identical content is not duplicated; folder attachments are not merged (harness)
- [ ] Receive a real attachment from a contact whose name clashes with a file uploaded from the phone → both kept

### Attachment source picker (#375) — implemented 2026-09-22

- [x] Files Upload opens the rmail "Add from: Gallery / File" dialog; Gallery then shows Android's app chooser (seen on device)
- [ ] Files `+` and Upload behave identically (both add to Files, no message)
- [ ] Write → attach uses the same dialog; picked items appear as attachments
- [ ] File route: Android offers file apps; the system picker opens on Recent (newest first)
- [ ] Multi-select works in both routes

### Save to device — implemented 2026-09-22

- [x] Files → Save → select an on-device and a server-only image → both land in `Pictures/rmail`, byte-identical, and appear in the media index (seen on device, Android 12)
- [ ] Video → `Movies/rmail`, audio → `Music/rmail`, other → `Download/rmail`
- [ ] Android 8-9: one system "Save as" dialog per selected file
- [ ] Saving the same file twice gives the system's own " (1)" name, not an overwrite

### Setup (#392) — 2026-09-22

- [ ] Public IP lookup happens only when "Detect public IP" is tapped (no ifconfig.me call on opening Setup)
- [ ] Connect with a wrong port → "Couldn't reach…"; wrong token → "didn't accept this token"; token without own=true → "not as one of your own devices"; "Save anyway" appears after a failure
- [ ] New mailbox: port field is blank

### Picker: Camera + remembered app — 2026-09-22

- [x] "Add from" shows Gallery, Camera, File and "Long press to change default app" (seen on device)
- [x] First Gallery tap shows Android's chooser; the pick is remembered and the next tap opens that app directly (seen on device)
- [x] Camera opens the camera app; cancelling adds nothing and queues no upload (seen on device)
- [ ] Taking a photo adds it to Files (from + / Upload) or to the message (from Write)
- [ ] Long press on a source shows the chooser again and the new pick replaces the old
- [ ] Uninstalling the remembered app brings the chooser back
- [x] Files action bars (Delete / Forward / Save) sit above the list; the first file stays visible (seen on device)

