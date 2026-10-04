# #new-the-android-app-and-its-sync — The Android app keeps a copy of each home mailbox, and syncs it

## Status

Completed — a blueprint written 2026-10-04 (#402) for what was built
before issue files described it (`clients/android/`, Kotlin with Jetpack
Compose).

## Current Behavior

**Mailboxes.**  The app holds any number of home mailboxes
(`mailboxes.json` in its private storage), each a `MailboxConfig`:

| field | type | meaning |
|---|---|---|
| `id` | string (UUID) | names the mailbox's folder in the app |
| `name` | string | shown in the list; learned from the server |
| `hosts` | list of strings | public addresses or hostnames, tried in order |
| `localHosts` | list of strings | private addresses, tried first, only from the same /24 |
| `port` | number | the home daemon's port |
| `token` | string | the phone's shared secret with it (`own = true` there) |
| `bgSyncIntervalMinutes` | number | background sync, at least 15 |
| `notificationDetail` | string | how much a new-mail notification says |
| `mailboxPath` | string | the home mailbox's folder, learned from sync |

**Storage** mirrors the home layout (`MailStore`): `mailbox-<id>/inbox/`,
`outbox/`, `attachments/` (a cache of downloads), `contacts`, and
`sync-state.json` (inbox message id -> file, outbox names known to the
server, the SHA-256 of each outbox file as last sent or received, the
contacts hash).

**Talking** (`RmailClient`): the same sealed frames as the daemons
(`crypto/Crypto.kt`), on one connection kept open across a sync's
requests.  `HostPicker` chooses the address: a local one on the phone's
own /24 first, each probed briefly — a private address on another
network is some stranger's device — then the public ones in order; the
one that answered is remembered for the rest of that sync (#388).

**A sync** (`SyncManager`), one at a time per app:

0. upload attachments still waiting on the phone, so their message can go
   in the same sync (#375, #404c);
1. work out the local changes: inbox files deleted, outbox files new,
   deleted or edited since last sent;
2. `POST /api/sync` (#new-the-phone-api);
3. apply the answer: remove, download (keeping the server's dates),
   upload new and edited outbox files, take or push the contacts — each
   step recorded in `sync-state.json` the moment the server confirms it,
   so a later failure never makes it re-send what already arrived (#386);
4. notify about new mail.

**When.**  While the app is open, syncs follow a backoff that mirrors
the daemon's timers — 30 s floor, +6 min per failure, 2 h ceiling, ± 30 s
jitter (`SyncBackoff`, #377).  In the background, Android's WorkManager
runs a sync of every mailbox every `bgSyncIntervalMinutes`
(`SyncWorker`).  Errors are put in words a person can read (#320).

## Intended Behavior

As above.

## Suggested Implementation Steps

1. `data/`: `MailboxRegistry`, `MailStore`, `Models`, `Settings`,
   `DeviceExport` (#378).
2. `net/`: `RmailClient`, `HostPicker`; `crypto/Crypto.kt`.
3. `sync/`: `SyncManager`, `SyncWorker`, `SyncBackoff`, `UploadProgress`.
4. Build: `scripts/compile-android.sh`.

## Related documents

- `docs/.templates/android-instructions.md`
- `#307`, `#308`, `#320`, `#375`, `#377`, `#378`, `#386`, `#388`, `#404c`
