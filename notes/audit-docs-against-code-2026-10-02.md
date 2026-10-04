# Audit: rmail's documents against its code (2026-10-02)

Asked for by the owner from rao-chat, after finding that two-way editing
was never shipped ("Oh weird then the readme is out of date. Can you do
an audit and see if there's anything else in the rmail docs that are not
reflected in the outcomes of the source-code? Pay special attention to
things like, timestamps and android permissions and stuff.").

How it was done: every claim in README.md, docs/.templates/*.md (the
docs/ files are generated from them by scripts/generate-docs.sh, so
fixes belong in the templates), the scripts and the Android client was
checked by reading the code, with file and line.  Nothing was run, so
everything here is "by reading".  Four findings were checked again by
hand (marked ✓).  Line numbers are rmail.lua's unless named, as of
commit 15897a4.

Issues opened from it: #312–#504 (the code bugs); the document fixes
were made in the templates the same day.

## Editing

The README says nothing about editing ("Deleting works both ways",
README:40, is the closest).  As shipped, only the author's edits travel:
`sync_outbox` compares the outbox body's checksum and sends `update`
(5145-5182); a recipient's edit to an inbox file is never sent
(`sync_inbox` looks only for deletions, 5540-5577) and is overwritten by
the author's next edit (`handle_deliver_update`, 2289-2291).  Two-way
"shared files" was tried and rejected (#708); `helpers/shared.lua` is
gone.

## 1. Data loss, security, consent

1. ✓ **Declining an attachment does not stop it.**  attachments
   template 85-87 says the sender removes the `attach:` line.  On decline
   the sender deletes the zip, writes `inbox/declined-<file>` and drops
   the transfer record (4459-4466); nothing removes the line (the only
   remover runs on completion, 4871), so the next cycle sends a fresh
   request under a new id (5070-5127) and the receiver gets a new consent
   form each time.  The receiver's form is removed, not replaced (3878).
   → #312.
2. ✓ **Cancelling or refusing an attachment removes the recipient from
   the message.**  Template 238-239: "The sender's daemon is notified
   automatically and stops sending."  The receiver's cancel (user cancel,
   oversize, bad zip) is sent as `/delete` with the *message's* id
   (3920-3926; `refuse_transfer` 4078-4086); the sender's `handle_delete`
   strikes the `to:` line, fires `on_delete` and deletes the outbox file
   when it was the last recipient (2468-2495, 2394-2396).  → #313.
3. ✓ **One recipient finishing takes the file from the others.**
   Template 23: "Both alice and bob get photo.jpg."  When any recipient's
   transfer completes, the shared `attach:` line is removed
   (4856-4874 → `remove_attach_from_file` 3553-3571); transfers for a
   recipient start only after its body is delivered (5042-5127).  → #314.
4. **Edits are lost when the contact is not due or not reached.**
   `state[name].body_checksum` is saved while the update is built,
   before it is sent (5182); a withheld or failed update (the per-contact
   gate, 3101-3103) is never retried.  #211's "Found while verifying"
   reports the same.  → #208.
5. ✓ **"Your name is not sent in cleartext" is false.**  encryption
   template 80, 97, 472; README:316.  The plaintext health check answers
   anyone with `{"ok":true,"name":<name>}` (6794-6803); install.sh 876-878
   admits it.  → #106.
6. **Replays are not prevented, and the documents do not say so.**
   encryption template 113-116 says an attacker cannot "change a message"
   or "send fake messages".  No nonce tracking, counters or times
   (6806-6837): a captured `/delete`, `/update-address`, or a `/deliver`
   of a since-deleted message can be sent again.
7. **Tokens leave the machine.**  encryption template 160-163: tokens
   live only in `contacts`.  Every `own` device is sent the whole contacts
   file, tokens included (5979-6030, 6146-6151, 6184-6186); the phone can
   post a replacement (6189-6204) — expected (owner).  Not expected: the
   phone is sent the contacts in canonical form (sorted, no comments;
   5979), and a save from the phone writes that text over `contacts` as
   it is, so every `//` comment is lost (checked by hand).  → #504.
8. **The router "security check" opens a port.**  nat-traversal template
   351-361 and README:290 say it probes.  When UPnP answers it adds a TCP
   mapping (port 60000+time%4000) and deletes it (1999-2005), at every
   start, even with `auto_port_forward` off; it does nothing without
   `upnpc`/`natpmpc` (1904, 1929); `own` contacts are skipped and a later
   RESOLVED notice is sent (2014-2041).  The `nat_mapping.json` example
   (341-347) shows other fields than the code writes (`protocol, port,
   created_at, lifetime`; 1972, 1982).
9. **Read-only-root advice is outdated.**  encryption template 382-390.
   Config and hooks now live in the writable mailbox (10-23, 191-216;
   install.sh 930-940), so hooks — runnable code — are on the writable
   side.
10. **Shared /tmp.**  `sha256_of_bytes` writes a predictable
    `/tmp/rmail-sha-NNNNNN` (3462-3468); pending pieces in
    `/tmp/.pending/<id>` and zips in `/tmp/rmail-<uuid>.zip`, shared by
    every mailbox (117, 3527, 4211); `/tmp/rmail-progress/` holds the log
    and progress files (127).  Undocumented.  (The owner: fine, unless a
    RAM folder other than /tmp can be used — the user's own
    `/run/user/<uid>` is one.)
11. **The auto-consent example cannot work.**  helper-scripts template
    98-115, defensive 355.  Consent forms never fire `on_receive`
    (`handle_attachment_request`, 3575-3697), and the path is `$3`, not
    `$2` (2246-2249).

## 2. Timestamps

1. Received messages take the sender's outbox-file modification time
   (#211), sent as `mtime` in deliver and update (5030, 5175, 5359, 5371),
   applied with `touch -m -d @N` clamped to 2001-09-09..2100-01-01
   (402-408, 2243, 2291).  An edit moves the file's time to the edit
   time; a wrong but in-range clock (future dates too) is accepted; a
   missing or out-of-range value silently becomes "now".  Undocumented.
2. Attachment times travel in the zip's extended-timestamp field, 32 bits
   ("loops in 2038"); the reader picks the 2^32 lap at or before arrival
   (zip-writer.lua 15-17, 146; zip-reader.lua 43-44, 103-111, 491-495).
   The DOS time field is UTC, 1980-2107 (zip-writer 63-74).  Phone
   uploads use Java `ZipEntry` with no extended time, so they are dated
   at arrival (RmailClient.kt 727-728).  #211 still says `unzip`
   preserves times — outdated since #309.
3. The phone sends and receives `X-Mtime` for inbox and outbox files
   (6170, 6966-6973; RmailClient.kt 241-257; MailStore.kt 37, 53);
   attachment downloads carry none.  The phone lists by file name, not
   time (MailStore.kt 30, 46), so #211's "the phone's list sorts the same
   way" is not what the app does.  The thin client keeps no times.
   Phone-composed names use local time with no zone (MainViewModel.kt
   371).
4. Logs, problem notices and the NAT marker use local time with no zone
   (756, 862, 2050).  The time helpers need GNU `stat -c` and
   `touch -d @` (395-408); without them, set_file_mtime fails silently.
5. protocol template 116-134 (one timer, "starts at 5 minutes",
   MIN/MAX_INTERVAL, "outbox changes … no timer needed") is outdated.
   Per-contact timers (#115): floor 30 s, +360 s per failed cycle, ceiling
   7200 s, ±30 s jitter (912-1008); a contact that connects is due now
   (6837); nothing queued → back to the floor (7078-7086); all due at
   start-up (7429-7437); an outbox change still waits for the timer
   (3090-3146; #119 open); chunks go through the same gate (4681).
6. README:324 and 366 ("retried on each sync cycle"), defensive template
   38-41 ("within seconds") and 116-117 ("default sync interval
   (minutes)") are outdated; scripting-tutorial 360-362 is about right.
7. Undocumented timers: public-IP recheck every 24-48 h, retry after 1 h
   if no provider answered (7154-7199); connect deadline 8 s (2944);
   receive 10 s, send 30 s (2719, 2737); DNS cache 60 s (522); NAT renewal
   every 1800 s, NAT-PMP lifetime 3600 s (1980, 7736); `--once[=SECONDS]`
   default 60 s plus up to 600 s (155-160, 7698-7701), undocumented.
   Phone: WorkManager every 15 min, no network constraint (SyncWorker.kt
   41-50; MailboxRegistry.kt 21); foreground back-off 30 s/+360 s/2 h/±30 s
   (SyncBackoff.kt 33-39).  Availability windows (#419) are not built.

## 3. Android permissions

Declared (AndroidManifest.xml 4-7): INTERNET, ACCESS_NETWORK_STATE,
POST_NOTIFICATIONS, RECEIVE_BOOT_COMPLETED.  No document mentions any.

- POST_NOTIFICATIONS: requested at run time on Android 13+
  (InboxScreen.kt 270-283; SyncManager.kt 404-431); a notification-detail
  setting (full / sender / none / off) is undocumented.
- RECEIVE_BOOT_COMPLETED: no receiver declared; WorkManager brings its
  own, so the line is redundant.
- ACCESS_NETWORK_STATE: used in setup (SetupScreen.kt 459).
- No storage permission: saving uses MediaStore on 10+ and the system
  "Save as" on 8-9 (DeviceExport.kt); folder picking via OpenDocumentTree
  (ComposeScreen.kt 162); the camera through the camera app
  (AttachmentSourcePicker.kt 209); share targets accept any type
  (manifest 30-41); backup and device transfer are excluded (manifest
  15-17; data_extraction_rules.xml).
- No foreground service, no battery-optimisation handling.

## 4. Configuration

1. README:148 and attachments template 251-252: "The generated config
   file contains a comment above every available key" — the generated
   config (install.sh 864-941) omits `attachments`,
   `attachment_pending_dir`, `attachment_chunk_size`, `log_file`,
   `allow_peer_address_requests`, `hostname`; the last three are
   documented nowhere (139-147, 177; 162, 6040; 1552).
2. Defaults match: `attachment_pending_dir=/tmp` (117),
   `attachment_chunk_size=5242880` (161), `attachments=<mailbox>/attachments`
   (116), ports 50000-65000 (install.sh 623-628); no default port (a
   missing port is fatal, 7215-7225).
3. Quotes are kept and `~` is not expanded for most keys (35-54,
   116-117); only hooks and `log_file` are cleaned.  attachments template
   197's `~/mail/attachments` makes a literal `~` folder; a quoted chunk
   size silently becomes the default.
4. No upper bound documented for `attachment_chunk_size`; bodies over
   50 MB are refused (2816), so a chunk above about 37 MB never arrives.
5. service template 284-285 names a `mail` setting that was removed
   (18-23).

## 5. Attachments, other

- README:88 and template 5 say "compressed chunks"; the packer stores
  (template 96 itself says stored; zip-writer 149, method 0).
- Consent-form examples (README:74-86, template 48-60) lack the
  "Attached to:" line (3668-3676).
- Template 76-83: the form is "replaced with a confirmation"; it is
  removed (4425-4431).
- Progress text (template 182-185, 231-235) is stale: the code says "To
  cancel: delete this file, or add a line that reads: deny" (4344);
  "Sending: …" before the first piece (3868-3872); the file is a link
  into /tmp/rmail-progress (#304).
- Template 218-219: deleting `transfers` cancels nothing (4545).
- "Capped at 128 KB … error, won't retry" (template 254-260; tutorial
  479-481; defensive 184-193): bodies over 131072 bytes become an
  attachment with a stub body (#308; 5216-5344); updates have no cap
  (5362-5371).
- Undocumented: the body waits for every attached file, with the
  `// MISSING ATTACHMENT` marker (5003-5033); the `attach:` line removed
  on completion; `name-2.ext` and identical content kept once
  (3957-3968); attachments kept when a message is deleted (#306); limits
  of 4 GiB per file and per zip, 65,535 entries, ZIP64 refused; phone
  transfers in 256 KiB pieces (6281); abandoned `.uploads` and pending
  pieces never expire.
- Correct: the 100,000-piece cap and 64 per answer (4111-4117); size ×
  1.1 + 4 KiB (4033-4035); nothing before consent (4205-4209); id format
  (3488-3490); link notes (#311a).

## 6. Deletion and hooks

1. README hook table (332-344) omits `on_update` ($1 sender, $2 inbox
   path, $3 new body; stdout replaces the body; 215, 2285, 5159) and says
   `on_delete` runs in the background — it is synchronous
   (477-487, 2440, 2474, 5555).
2. "Non-zero exit keeps the body" (tutorial 49, 321-322;
   scripts/hooks/on_update.sh) is false: the exit status is never read;
   any non-empty stdout replaces the body (477-487, 2236-2237).
3. `on_delete` fires when the *other* side deletes (2474), on inbox
   deletions (2440, 5555, 6082) and for mail to oneself (4790, 4805) —
   not for one's own outbox deletion — and gets only the other party's
   name.  So README:48's backup of old messages cannot use it.
4. `on_send` also runs for every edit and for mail to oneself
   (5353-5371, 4975-4978); `on_receive_raw` does not run for updates, so
   the padding pair in encryption template 200-230 leaves padding in
   edited messages.
5. defensive template 86-110 (heartbeat) is broken: its `subject:` line
   becomes the first body line, and `rm "$2"` with empty stdout deletes
   nothing (2284-2291).
6. Hook path rules (relative to the config's folder, `~`, `""` disables;
   185-207) are only in install.sh comments.
7. README deletion bullets (40-46) are correct.

## 7. Protocol (protocol template)

- HTTP/1.0 shown; the daemon uses 1.1 with keep-alive (2847-2853,
  6786-7020).
- The payload omits `mtime`, `auto_body`; the address announcement omits
  `ips`, `local_ips` (5938-5941); the type table omits `update`,
  `attachment_chunk`, `chunk_failed` (4771-4777).
- Missing endpoints: `/api/consent`, `/api/log`, `/api/upload/resume`,
  `/api/attachments/<f>/info`, `/api/attachments/<f>/chunk/<n>`,
  `DELETE /api/attachments/<f>` (6931-7006); encrypted `GET /deps`,
  `/deps/<n>`, `/install-script` (6903-6917); `/api/myaddress` also gives
  `ipv6` (6054).
- Unstated limits: frames 28 bytes to 64 MiB (2741); bodies 50 MB (2106).
- Correct: framing, SHA-256 key, trial decryption, plaintext `GET /`.

## 8. Commands, scripts, platforms

- README:266-269: the router validator does not read the port by itself;
  it needs the mailbox or config (validate-router-settings.sh 21-30);
  encryption 366 the same.
- README:94 "Lua 5.1+": the daemon uses `goto` (2923) and zip-compat
  errors on load under 5.1/5.2 (zip-compat.lua 30-51); it needs LuaJIT
  or 5.3/5.4 (DEPS_REGISTRY's "5.1", 227, is stale too).
- README:322-326 "Dynamic IP": DNS queries to OpenDNS, Cloudflare and
  Google (5717-5729), at start-up and every 24-48 h; every start-up
  announces to all contacts (7398-7427); the notice is a hidden
  `.address-update-<name>` file, removed after the next successful send
  (2679-2683, 7067-7071).
- service template 301-304: no config link is made in the project root.
- Logs: the daemon's own rotating log (`/tmp/rmail-progress/log-<path>`,
  5 MB plus one old copy; 139-147, 720-769) is undocumented and
  `view-logs.sh` does not find it; android-instructions 237-243, 358-360
  (`/var/log/rmail…`, service `rmail`), thin-client 276 (`/tmp/rmail.log`)
  and the NixOS section of service (204-225) name the wrong places — the
  real ones are `/tmp/rmail-<path>.log` and `rmail-<path>`
  (install.sh 1785-1850).
- Thin client: installers are `install-thin-client-{linux,macos}.sh` and
  `install-thin-client-windows.bat` (thin-client 66, 83, 102, 116, 284);
  `--port` defaults to 8025 only at the prompt (rmail-client.lua 33-85).
- Android guide: the public IP is fetched only on "Detect public IP"
  (SetupScreen.kt 66-80, 246); "Detect port" scans the entered host then
  254 LAN hosts (373-420), not Wi-Fi only; the back arrow, three-dot menu
  and pencil were replaced (#817; InboxScreen.kt 300-382); phone
  Accept/Deny undocumented.
- ports-explained 186: the phone only talks to its home daemon.
- README:224-245 opens TCP only; the daemon also binds UDP, uses multicast
  239.192.82.77, and probes the /24 (7373-7377, 6604-6688).
- GNU tools hard-wired (`stat -c`, `touch -d @`, `df --output`, `du -sb`,
  `find -printf`, `sha256sum`, `ip`; 396, 407, 3441, 3449, 3500, 3456,
  1868) though a kqueue path exists (341-359).
- docs/attachments.md is older than its template (before #309); rerun
  `scripts/generate-docs.sh`.

## Checked and found accurate

Contacts syntax and `ip[N]`/`port[N]` (README:150-186); one port for both
directions; AES-256-GCM framing, SHA-256 key, trial decryption
(README:311-318); NAT renewal every 30 min; renaming a contact; mail to
oneself; `rto`/`rattach`/`raccept`/`rdeny`/`rfield`; no `--config` flag;
AMBIGUOUS RECIPIENT; the #311 chunk rules; `own = true` gating `/api/*`.

Not checked (needs running): the duplicate-message race when two daemons
dial each other at once (#211), and recovery of an interrupted transfer
after a reboot wipes /tmp.
