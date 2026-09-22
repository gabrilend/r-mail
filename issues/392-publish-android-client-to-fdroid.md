# #392 — Publish the Android client on F-Droid

## Goal

Someone who has never heard of rmail finds it on F-Droid, installs it, and
gets from first launch to a first message without a developer standing
next to them.  Today that is not possible, and F-Droid's reviewers would
also stop on a few points of their own.

**Blocked by every item below.**  Existing issues are named by number;
problems with no issue yet are listed as B1-B20 and should each become one
(or be fixed directly and struck off here).

## F-Droid inclusion itself

What is already fine (verified 2026-09-22): dependencies are AndroidX,
Compose, WorkManager, documentfile and coroutines only -- no Play Services,
Firebase, analytics or crash reporting; repositories are google() and
mavenCentral() only; the only tracked binary is gradle-wrapper.jar; the
build needs nothing outside the repo; LICENSE is AGPL-3.0-or-later.

- **B1. applicationId.**  `com.rmail.app` is generic, and an applicationId
  cannot change after publishing.  Decide once: keep it, or move to a
  reverse-domain name the project controls.
- **B2. Versioning and tags.**  `versionCode = 1`, `versionName = "1.0"`,
  and no git tags.  F-Droid's update checks need tags or a rising
  versionCode.  Pick a scheme and tag the first release.
- **B3. Store metadata.**  No `fastlane/metadata/android/en-US/` --
  title, short and full description, screenshots, changelogs.  The
  description must say plainly that the app is a client for an rmail
  daemon you run yourself.
- ~~**B4. Third-party network calls without consent.**~~ *Fixed 2026-09-22: the public-IP lookup runs only when "Detect public IP (asks ifconfig.me)" is tapped.*  Setup fetches
  `https://ifconfig.me/ip` and `https://icanhazip.com` the moment it opens
  (`SetupScreen.kt`).  Make it a button the user presses ("find my public
  IP"), or ask the daemon (`/api/myaddress`) once connected.  Otherwise it
  needs disclosing, and reviewers may flag it.
- **B5. Setup guide link.**  Hardcoded
  `github.com/gabrilend/r-mail/...` with a comment saying to update it once
  the docs are published.  It has to point somewhere real and public.
- **B6. Repository hygiene before the repo goes public.**  `issues/371`
  contains a third party's IP address; `llm-transcripts/` and `notes/` are
  tracked.  Decide what is published.

## First launch

The app opens straight into Setup, which assumes you already run a
daemon, know your router's public IP, and have edited a contacts file on
the server.

- **B7. You need a server, and nothing says so.**  The largest barrier by
  far: a working rmail needs a daemon on an always-on machine and, for use
  away from home, a forwarded port.  First launch needs a welcome screen
  saying what rmail is, what you need, and where to get it (install.sh, a
  portable drive -- #339, #361, #385 -- later a router, #390), before any
  field asks for an address.
- **B8. Pairing is a config-file edit.**  (A QR code is possible from a
  headless daemon: `qrencode -t ANSIUTF8` draws one in the terminal.)  The help text is a raw snippet
  to paste on the server (`myphone.token = "<your-token>"`,
  `myphone.own = true`).  "Device token" is jargon, in a password field
  wrapped in literal quote marks.  Wanted: the daemon prints (or shows as a
  QR code) everything the phone needs -- address, port, token -- and the
  phone takes it in one step.
- ~~**B9. Wrong default port.**~~ *Fixed 2026-09-22: the field starts blank.*  The app pre-fills 8025; install.sh picks a
  random port in 50000-65000.  The pre-fill is wrong for almost everyone.
- **B10. "Detect port" scans.**  (Not against F-Droid's rules -- scanners
  are listed there -- but a bad first impression and noisy on networks.)  It tries every port on one host, and its
  LAN fallback about 3.8 million connections.  Slow, and indistinguishable
  from a port scan to anything watching the network.  Replace it with B8's
  pairing, or LAN discovery the daemon answers.
- ~~**B11. "Connect" does not connect.**~~ *Fixed 2026-09-22: Connect tests TCP reachability, then the token and own-device flag, and says which is wrong; "Save anyway" keeps the settings if the server is just off.*  It saves and moves on; a wrong
  token or address shows up later as a red sync-error banner.  Test the
  connection and say what is wrong, in words, before leaving Setup.
- **B12. Router talk.**  "Home router IP", auto-filled with whatever
  network the phone is on now (wrong away from home), and a "Network info"
  section about the default gateway, with no explanation of port
  forwarding.
- **B13. Navigation.**  Setup opened from the mailbox list has no back
  or cancel.  After the first setup, the navigation to the inbox uses
  `popUpTo("mailboxList")`, which is not on the back stack yet, so Back may
  return to Setup (unverified on a device).
- ~~**B14. Notifications never appear on Android 13+.**~~ *Fixed 2026-09-22: requested when the inbox opens, while missing.  Not seen on a device yet (the test phone is Android 12, which needs no permission).*  POST_NOTIFICATIONS
  is declared but never requested, so the first new message is silent.
  Ask at a sensible moment (after setup, not on launch).
- **B15. Error messages.**  The sync banner shows internal wording ("wrong
  token or tampered response", "retrying in 0m") and sometimes raw
  exception text.  Each needs a sentence a user can act on.
- **B16. Empty states.**  Empty inbox says "No messages" and nothing
  else.  First launch should say how to add a contact and send a first
  message.  The new-contact form asks for IP octets, port, token and
  "custom fields" -- daemon vocabulary throughout.
- **B17. Developer leftovers visible in the UI.**  The mailbox info
  dialog shows the internal ID; the notification icon is Android's stock
  email icon.
- **B18. Dead code.**  `SettingsScreen.kt` is imported but never routed
  (the live settings are a panel in InboxScreen).  Delete it so nobody
  maintains the wrong one.

## Data safety

- ~~**B19. Secrets in backups.**~~ *Fixed 2026-09-22: allowBackup=false, plus data-extraction rules excluding everything from cloud backup and device transfer.  No token was ever in git (all six checked against full history).*  `android:allowBackup="true"` sends the
  stored tokens -- the encryption secrets -- to Android device and cloud
  backup.  Set it to false or add backup rules that exclude
  `mailboxes.json`.
- **#378 Export mailbox.**  Mail lives in app-private storage; uninstalling
  loses it with no way out.  A public app needs an export.

## Existing issues that would hurt a first run

- **#372 Loopback drops attachments.**  The first thing a new user does is
  send themselves a test message with a photo.  It must work.
- **#311 NAT warning does not say who sent it.**  Confusing on first
  contact.
- **#314 Third-party outbox security.**  Not a bug today; a rule any
  public build must keep (only the app's own UI writes the outbox).  Check
  before release.
- **#386 Sync state all-or-nothing.**  Fixed in 01b0175; confirm with QA
  and close.
- **#313 Keyboard scroll.**  Probably fixed (bringIntoViewRequester is in
  place); confirm and close.

## Docs

- **B20. `docs/.templates/android-instructions.md`** says the app is "not
  on the Play Store or F-Droid (yet)" and walks through an adb build from
  source.  Rewrite for an F-Droid install once the above is done.

## Not blocking

Release values are already sane: the testing intervals noted in project
memory were replaced by backoff (30s floor, 2h ceiling) on both phone and
daemon.  `remoteLog` posts only to the user's own daemon -- worth a line in
the description, not an anti-feature.  Permissions (INTERNET,
ACCESS_NETWORK_STATE, RECEIVE_BOOT_COMPLETED, POST_NOTIFICATIONS) are all
justified.

## Status

Open.  Survey done 2026-09-22; nothing started.
