# #714 — Public capability-URL web server ("send to a browser")

## Current Behavior

Nothing is built: the daemon serves only the sealed protocol and the
plain one-line health answer (#106); there is no web server and no
reserved `to:` word.  The design below is complete apart from "Still
open".


> Renumbered from #615 on 2026-09-21: #615 was taken by
> `615-daemon-source-offer-and-build-identity.md`, filed on another
> machine and pushed first.

## Intended Behavior

Let a user publish a single outbox message as a **public web page**
anyone can open in a browser — no contact entry, no token, no rmail
client, from anywhere on the internet.  You write a message, mark it as
public, and rmail hands you a URL (appended to the outbox file).  Whoever
has the URL sees the message rendered plainly, with images shown inline
and other files offered as downloads.

This is a *capability URL*: possession of the (hard-to-guess) link is the
only credential.  Served over plain **HTTP** by choice (see Transport).

## Trigger: a reserved `to:` keyword

Instead of `to: alice`, the user writes the reserved recipient name that
means "publish publicly":

```
to: url
attach: ~/pictures/sunset.jpg

Here's the sunset I promised.
```

**Decision (2026-07-11): the reserved keyword is `url`** (`to: url`),
case-insensitive.  (Aliases could be added later; one is enough for now.)

- **Collision with a real contact.**  Today the only special recipient
  is `my_name` (self-delivery, `rmail.lua:3332`); anything else must be a
  real contact or it's flagged `// UNKNOWN CONTACT` (`rmail.lua:3380`).
  Reserve the keyword name: refuse to create a contact with it, and
  always treat it as publish.
- **Mixed recipients** (`to: alice` + `to: url`) compose — publishing is
  independent of delivery.  But the outbox uses the **cascade** rule
  (README: "each recipient receives all `attach:` lines that appear below
  their `to:` line"), so `to: url` publishes *every* `attach:` below it —
  including one intended for a later recipient.  Users should keep public
  files in the `to: url` block.  **Open question:** does the publish path
  need a guard against a private attachment below `to: url` being exposed
  publicly, or is that on the user (consistent with cascade elsewhere)?
  (Answered 2026-10-04: no guard; `url` follows the contact rule. See
  "Decisions (2026-10-04)".)
- A `URL:` line already present on the file *also* marks it for hosting
  (see Lifetime) — so detection is "has a publish `to:` keyword **or** a
  `URL:` field."

## Transport: plain HTTP (decision — no certs)

rmail's existing listener (`rmail.lua:1343`) is raw-TCP + AES-256-GCM
keyed by `SHA-256(token)` — no browser can speak it.  This feature is a
**separate plain-HTTP listener** on its own port.

**Decision (2026-07-11): no TLS, no certificates** — self-signed or CA.
The slug *is* the shared secret, and the deploy stays zero-config.

**Accepted tradeoff — the URL is not encrypted in transit.**  The slug
rides in the HTTP request line (`GET /ivory-chair-… HTTP/1.0`), which
over plain HTTP is cleartext on the wire: an on-path observer (ISP, café
wifi) can capture the capability key, and the served content is equally
visible.  The link is still unguessable to the public (slug entropy),
but it is *not* confidential against someone who can watch the
connection.  This is understood and accepted.

*Future option, not shipped:* the only way to hide the URL in transit
without a domain is a **self-signed cert** (LuaSec is already bundled —
`libs/ssl.lua`/`ssl.so`/`openssl`), which encrypts the path at the cost
of a browser warning.  Leave hooks for optional `public_tls_cert` /
`public_tls_key` config keys so it can be flipped on later, but ship
plain HTTP.

- Port is **configurable** (`public_http_port`, default e.g. 8028),
  bound `0.0.0.0` / `[::]`.  Needs its own firewall opening + router
  port-forward, like 8027.
- Routes only (no directory listing, no traversal):
  - `GET /<slug>` → the message's HTML page
  - `GET /<slug>/f/<attachment>` → one attachment (image/media inline,
    others as download, PDF inline so the browser tab renders it)
  - anything else → `404`
- Lives in the existing select/coroutine event loop (`rmail.lua:5110+`)
  as a second plain accept socket.

## URL slug: hand-alternating dictionary words

Dash-separated words, randomized, where letters **alternate typing
hands**.  Hand sets (standard touch-typing split):

- **Left:**  `q w e r t  a s d f g  z x c v b`
- **Right:** `y u i o p  h j k l  n m`

**Exact rule (confirmed):**

- Within every word, consecutive letters alternate hands.
- **The dash goes to the left hand** — i.e. every word **starts on the
  left hand**, *except the first word, which starts on the right hand.*
- So word 1 is R,L,R,L…; words 2..n are L,R,L,R….

Example: `ivory-chair-signal-dormant-visual`
(`ivory` starts right; `chair`/`signal`/`dormant`/`visual` start left).

- **Word count is configurable** (`public_url_words`) so it can be raised
  over time.  Config comment: *"recommend 5+ words as of 2026."*
  (Entropy: `W` qualifying words, `k` picks → `k·log2(W)` bits; a few
  thousand words ≈ 11 bits each, so 5 words ≈ 2^55.)
- **Wordlist:** filter a system dictionary (`/usr/share/dict/words`) by
  the alternation rule once and bundle it; **fallback** to random
  alternating-letter strings (same rule, not real words) when no
  dictionary is available.

## Rendering (no JavaScript, ever)

> **Superseded 2026-10-04** for how the page is delivered: the message
> now arrives encrypted and the decrypter script renders it (see
> "Decisions (2026-10-04)").  What it renders — the layout, media
> handling and theme below — still stands.

Plain HTML + inline CSS (CSS is fine; "no JS" = no scripts, nothing
external loads):

- **Message body** centered on the page — "nothing but the message."
  HTML-escaped; line breaks preserved.
- **Images** (jpg/png/gif/webp…): inline **underneath** the message
  (`<img src="/<slug>/f/<name>">`).
- **Video / audio**: in-page `<video>` / `<audio>` tags (still no JS).
- **Every inline image, video, and audio** is followed by its own
  explicit **"download this file"** link, so rendered media can also be
  saved directly (served `Content-Disposition: attachment`).
- **PDF**: a **link that opens a new tab** (`<a target="_blank">`),
  served `Content-Type: application/pdf` inline so the browser renders it.
- **Everything else**: a **download link** (`Content-Disposition:
  attachment`).
- Content-type by file extension (no libmagic); needs a small ext→mime
  table.

### Theme — respect `prefers-color-scheme` (pure CSS, no JS)

| | Background | Text | Borders / structural elements |
|---|---|---|---|
| **Dark**  | pitch black | bright red | yellow |
| **Light** | mottled gray | dark green | brick red |

- Switch via `@media (prefers-color-scheme: dark)`.
- "Structural elements drawn" = visible borders/rules/frames around the
  message and file sections, in the accent color per theme.
- "Mottled gray" achieved with CSS gradients (e.g. layered
  `repeating-radial-gradient`) — no external image, no JS.

## Attachments & directories (a browsable viewer, not a zip)

Which files a page publishes follows the normal **cascade** rule
(README / `docs/attachments.md`): the `to: url` "recipient" publishes
every `attach:` line below it.  Users should keep public files in the
`to: url` block (see the mixed-recipients exposure caveat above).

A published **file** is one entry: image/video/audio inline + a download
link, PDF a new-tab link, else a download link — served on demand, lazily
(a 2 GB video costs nothing until requested).  Nothing is inlined into the
HTML except the `<img>`/`<video>`/`<audio>` tags pointing at the file
routes.

A published **directory is not zipped** into a blob and not flattened
into one long link list.  It becomes a **browsable directory viewer** —
navigable, capability-scoped, no JavaScript.

### One slug per shared directory; real paths below it

An earlier draft gave every subdirectory its own slug and chained them in
the URL.  That was overkill (a five-word slug per level → huge URLs) and
clumsy for deep trees, and its only real payoff — capability-scoped
subtree sharing — isn't needed.  So: **the slug names the shared root
directory (the folder in the `to: url` file), and everything below it is
an ordinary relative path.**

```
/ivory-chair-signal-dormant-visual/photos/vacation/beach.jpg
 └─ slug = the shared directory        └─ real path under it
```

- `GET /<slug>` → viewer for the shared root.
- `GET /<slug>/<subpath>` → viewer for that subdirectory, or the file
  itself if `<subpath>` names a file.
- `GET /<slug>/<subpath>/download.zip` → that folder, zipped on command.

**Up-navigation is trivial and unlimited:** strip a trailing path
segment.  Down N levels, up N levels — no stored context, because the
full path *is* the context.  The viewer shows an "up" link whenever
there's a segment left to strip (i.e. you're below the root).

### Scope & security — path traversal is now the guard

The slug is the capability for the **whole shared tree**: anyone with it
(or any URL under it) can browse the entire folder, up to the root and
down anywhere.  Real file/dir **names appear in the URL** — not secret
(nothing on the public path is), just navigational.

Because the URL now carries **real path components** (it didn't under the
old opaque-slug model), **path traversal is the critical guard**:

- reject `..` segments and absolute paths outright;
- resolve the requested path and **hard-verify it stays inside the shared
  root** (canonicalise, compare prefix) — including no escape via symlink;
- unknown slug, or a path that resolves outside the root → flat `404`.

No `.state` mapping is needed: the slug → root-directory binding lives in
the outbox `URL:` line; everything below is resolved live against the
folder on disk each request.

*Dropped: per-subfolder capability scoping.  If sharing a subfolder
without exposing its ancestors is ever wanted, mint a fresh root slug
pointing at that subfolder (a "re-root") — no per-folder slug machinery.*

### Open decisions

- **`download.zip` scope** at a subpath: zip just that subdirectory
  (relative to it), vs always the whole root — confirm the intent.
- Show file sizes / entry counts in the listing (cheap `stat`, nicer UX)
  or keep the page minimal?

### Zip-on-command download mechanics (no JS — HTTP does it)

> **Superseded 2026-10-04**: files now arrive encrypted, in pieces the
> decrypter checks, stores and joins (see "Decisions (2026-10-04)").
> Kept as the record of the plain design; the notes on where a cache
> may live (`/dev/shm`, not `/tmp`) still apply to anything cached.

The download experience (stream, resume, buffer-to-disk) is **native HTTP
+ browser**, not something we build in JavaScript.  A plain
`<a href=".../download.zip">` (no JS) triggers it; the daemon zips the
directory on command and returns `Content-Type: application/zip` +
`Content-Disposition: attachment`.  The browser handles the rest —
progressive receive, RAM→disk buffering (its job, not ours; we can't
read a visitor's RAM from the server, even with JS), and progress UI.
There is **no** client-side de-chunk/reassemble and **no** bundled
mini-rmail; rmail's chunk+SHA-256+token protocol is the encrypted
daemon↔daemon channel and does not cross to browsers.  On the public path
it's plain HTTP (no-certs decision) — the slug is the *capability*, not
an encryption key; nothing is encrypted in transit.

**Zip style** differs from delivery on purpose.  `compress_attachment`
uses `zip -rj`/`-j` — **junk paths (flatten)** — because it ships a single
attachment.  A folder download wants the opposite: `zip -r` **preserving
structure** relative to the shared root, so the visitor gets the real
tree.  Separate zip call, not a reuse; and no rmail chunk/SHA-256/token
wrapping (that's the encrypted daemon channel).

**Cache hit = send immediately, don't re-zip.**  Only zip on a miss; if
the zip already exists, serve it straight away (with `Accept-Ranges`).

**Resume** is HTTP **Range requests**, which forces the stream-vs-cache
call:
- *Stream `zip -r` to the socket* — nothing stored, but a live stream
  isn't seekable, so **no resume**.  Right for huge folders.
- *Pre-zip to a cache dir, then serve with `Accept-Ranges: bytes`* — the
  file is seekable, so an interrupted download **resumes** (`Range:
  bytes=N-` → `206`) and repeat hits are free.  If the cache was cleared
  (reboot), it regenerates and restarts from scratch.

**Cache location — `/tmp` is *not* RAM on all hosts.**  On the sorelu box
`/tmp` lives on the root ext4 disk (only `/dev/shm`, `/run` are tmpfs);
the "RAM-backed /tmp" comments elsewhere in the code are wrong there.  So
if a RAM cache is wanted, use **`/dev/shm`** (guaranteed tmpfs), not
`/tmp`.  Either way the cache needs a **size cap / LRU eviction** — a 2 GB
folder zipped into RAM would be brutal — and very large folders should
prefer the streaming path over caching.

The resume requirement points at **pre-zip-to-cache + Range support** for
normal folders, streaming for huge ones — reproducing the intended
RAM/resume/restart behavior with the browser doing the client half for
free.  (Feature note kept here per request — revisit when building the
download route.)

## Lifetime & persistence — outbox is the source of truth (no state file)

**No `.state` mapping.**  The outbox files themselves hold everything:
the publish `to:` keyword and the appended `URL:` line.  The `/tmp` HTML
is a *derived cache* that's regenerated and pruned each cycle.

**URL generation.**  When a publish-marked outbox file has no `URL:` yet,
generate a slug, then **append it at the very bottom of the outbox file
after a blank line** — `\n\n` + a labeled line
`URL: http://<host>:8028/<slug>` — and generate the page's HTML into
`/tmp`.  The user can **edit that line afterward**; the parser locates it
by the `URL:` label anywhere in the file.  A hand-edited slug that breaks
the alternation rule is **accepted as-is** (the rule only governs
auto-generation).

**Each sync cycle** (hook into `run_sync_cycle`, `rmail.lua:4975`):

1. Iterate every outbox file.  For each that is publish-marked or carries
   a `URL:` line:
   - if it has no `URL:` → generate one, append it, generate HTML in `/tmp`;
   - ensure its HTML exists in `/tmp` (regenerate if missing);
   - add its URL → served file(s) to the server's serve-list; record the
     URL as "seen this pass."
2. After the full iteration, **prune** any serve-list entry / `/tmp` HTML
   **not seen this pass**.

This handles renames/edits naturally: editing the `URL:` line makes the
next cycle create the new URL + HTML and prune the old one (the old URL
simply isn't "seen" anymore).  Deleting the outbox file un-hosts it.

**The server only ever serves files that live in `/tmp`.**  So `/tmp`
being cleared (reboot) just means "regenerate," never "lost data" — the
outbox is authoritative.

## Startup + logging

On startup, regenerate any missing HTML (same iteration as a sync cycle:
find publish/`URL:` outbox files, generate pages absent from `/tmp`), and
**log one line per hosted file**:

```
hosting outbox/sunset-promise at http://<host>:8028/ivory-chair-signal-dormant
```

Beyond startup, **emit a line whenever a hosted file is newly discovered
(a new URL generated) or pruned** during a sync cycle:

```
public url added:  http://<host>:8028/ivory-chair-signal-dormant  (outbox/sunset-promise)
public url pruned: http://<host>:8028/old-slug                    (source gone)
```

Logs go to **`/tmp`** (RAM-backed `/tmp/rmail.log`, `view-logs.sh:16`),
and the **install directory should carry a symlink to that log** — same
tmpfs+symlink pattern already used for `TMPFS_PROGRESS_DIR =
"/tmp/rmail-progress"` with its mailbox-path symlink (`rmail.lua:340-350`).

## Config keys (all editable in `config`)

Read via the existing `parse_config_file` (`rmail.lua:32`, `key = value`):

```
# public browser-facing HTTP server for `to: url` messages
public_http_port = 8028
# words in a generated URL slug — recommend 5+ words as of 2026
public_url_words = 5
# (future/optional) TLS — NOT shipped; plain HTTP by default. If set,
# encrypts the URL in transit at the cost of a self-signed browser
# warning (warning-free would need a domain + CA cert).
# public_tls_cert = /path/cert.pem
# public_tls_key  = /path/key.pem
```

## Security

- **Capability URL** — anyone with the link gets the content; slug
  entropy (configurable words) is the only guess barrier.
- **Plain HTTP (no TLS), by decision** — the URL and content travel in
  cleartext; an on-path observer can capture the capability key.
  Unguessable to the public, but not confidential in transit.  (Optional
  self-signed TLS left as a future config hook.)
- **Path scope** — serve only that message's attachments; sanitize
  `<attachment>`; no traversal, no directory listing, no access to other
  outbox files or the mailbox.
- **Opt-in per message** — nothing is public without the reserved
  keyword.
- Consider connection/rate caps on the public port.

## Decisions (2026-07-11)

- **Trigger keyword:** `url` (`to: url`).
- **Transport:** plain HTTP, no certs — URL-in-cleartext tradeoff accepted.
- **Hand-edited slug that breaks the alternation rule:** accept as-is.
- **URL marker:** a labeled `URL:`-prefixed line, located by its label
  anywhere in the file (e.g. `URL: http://<host>:8028/<slug>`).

## Decisions (2026-10-04)

- **Wordlist:** ship a ready-made list with rmail, which users can add
  to (owner: "let's ship a ready-made list that users can add to").
- **`url` is treated as a recipient**, going through the same mechanisms
  as a contact (owner: "it should probably pass through the same
  mechanisms", and "treat the to: url as a contact, so, only send them
  the correct attachments and such").
- **Attachments follow the contact rule**: `url` gets every `attach:`
  below its `to:` line, exactly as a contact does, so an author who
  wants a file kept off the page puts `to: url` after it.  Owner: "we
  should try and keep behavior consistent as possible, and re-use as
  much machinery as we can."  This answers the cascade question under
  "Trigger": no extra guard.
- **What `url` re-uses, and what it skips** (owner: "this sounds like
  the right shape"): it re-uses the choice of which files belong to a
  recipient, and withdrawal (removing `to: url` takes the page down);
  an edit shows on the page by itself, since the page is read from the
  outbox file at each visit.  It skips consent (there is nobody to ask)
  and sending in pieces (a browser fetches a file itself).
- **Encrypted, with the key in the link; no HTTPS** (owner: "can't do
  HTTPS because certificate", and "the url kinda needs javascript").
  This replaces the 2026-07-11 plain-HTTP decision and "no JavaScript,
  ever": the rule is now **no JavaScript except the decrypter**.  It
  overturns "Rendering", "Zip-on-command download mechanics" and the
  slug's role in "URL slug" below, which describe the plain design.
- **One secret, not two** (owner: two long keys are "gonna be hard to
  write down on a post-it", and the point is to work like a QR code for
  someone without rmail).  The hand-alternating words of "URL slug" *are*
  the key.  The browser derives two things from them: the address it
  asks the server for (a hash of the words) and the decryption key (a
  deliberately slow derivation of the words, so each guess costs a
  stolen copy's owner real time).  The server stores and serves each
  published message under the hash only; it never sees the words.
- **The words go after `#`, or are typed in** (owner: "if there isn't a
  # attached to the link, the user could get a pop-up by the decrypter
  saying 'yo what's the code'").  `http://host:port/#ivory-chair-…`
  opens directly; `http://host:port/` alone shows the decrypter with a
  box asking for the code.  So a post-it can carry the address and the
  code separately, or a QR code can carry both.
- **Files arrive in pieces kept on disk until whole** (owner: "Write the
  fractional files to disk once we've validated that they're confirmed,
  and only combine them when they've fully arrived ... like how rmail
  normally functions, except through a browser").  Each piece is
  encrypted on its own, so decrypting it also proves it arrived intact
  (the cipher's check fails on any change).  The decrypter writes each
  checked piece to the browser's private storage on disk (the Origin
  Private File System, in current Firefox, Chrome and Safari), so a
  reload or a dropped connection resumes from the first missing piece;
  once every piece is there it joins them and hands the file to the
  browser to save.

## Known limitations (to address once feature-complete)

- **Tampering on the way.**  Over plain HTTP, someone positioned on the
  network path can replace the decrypter with a script that sends the
  code elsewhere.  The key in the link stops anyone who only *watches*
  the traffic, not anyone who *changes* it.  Owner: "I guess we gotta
  note that limitation."
- **Space twice over.**  Joining the pieces and saving the file needs
  room for both briefly; browsers also cap their private storage at a
  share of free disk, and a private window may not keep it.
- **JavaScript turned off** means the page cannot be read at all; the
  page should say so in plain HTML.

## Still open
- **How many words, and how slow the unlock.**  The code is now also the
  key, so its length is what protects a message whose ciphertext was
  copied.  Proposed: 6 words, and an unlock tuned to about a second on
  a phone; the issue's "5+ words" was set when the words only had to
  resist guessing against the server.  Asked 2026-10-04.
  *Answered in part 2026-10-09:* "6 words is fine, but we should be
  allowed to use as many as we want" — 6 by default, no upper limit
  (`public_url_words`).  On the unlock's slowness the owner asked what it
  means, adding: "Remember this token is in cleartext, so it's not really
  encrypting anything from a determined attacker. It'll be posted
  directly on the website, so..."  Explained the same day (a slow unlock
  only protects a link that is *not* published).  Then: "unlock speed is
  irrelevant because a determined cracker would just make their own
  hacking tools that do not have such a delay" — not quite how a slow
  unlock works (the delay is work every guess must do, not a pause a
  tool can skip), said back the same day; but the outcome stands: **no
  slow unlock**.  The protection comes from the number of words, which
  the owner may raise freely.
- **What this is for** (the owner, 2026-10-09, correcting a drift): "for
  allowing an rmail user to send files or messages to someone who doesn't
  have rmail, and only has a browser, and doesn't have the ability to
  open ports on their system."  A link is handed to one person, not
  posted publicly.  And: "We might be able to set it up so they can
  respond, using shape A" — the website-contact way in (#420): a reply
  box on the page, sealing in the browser.  Proposed the same day: each
  published message gets its own listen-only contact, whose token is
  derived from the link's words (so only someone holding the link can
  reply, and nothing secret is in the page's files), the reply posted to
  the same address that served the page; removing `to: url` removes the
  contact and refuses later replies.  Waiting on the owner.
  *Answered 2026-10-09:* links may be private **or** public — "We won't
  tell our users how to use our software, only how to use it correctly.
  So we need to assume that they're going to use it for public and
  private purposes" — and replies should be many, "ideally ... essentially
  a chatroom".  So the page shows a conversation, not one message: the
  readers' notes (in through the listen-only contact) and the author's
  answers, kept on the server locked with the link's key, the page
  asking for new ones while open.  *Settled 2026-10-09:* a reader's note
  shows "at once, or after a refresh period. A sync cycle haha" — the
  page asks again each sync period; readers may not remove their own
  notes; "only the original 'to: url' sender can delete or edit messages.
  Also, only they can send attachments."  And the listen-only contact
  "should be hidden from the user. It is part of the 'to: url'
  pipeline": rmail makes and removes it itself, kept in its own state,
  never written into the contacts file.
- **Tampering is critical** (the owner, 2026-10-09: "This is a critical
  concern, we need to make sure it works correctly"), replacing the
  2026-10-04 "I guess we gotta note that limitation".  Over plain http a
  browser cannot tell the real decrypter page from a substitute: anyone
  able to *change* traffic on the way (a hostile Wi-Fi, a compromised
  router or provider) can serve a page that sends them the words.  What
  the lock already ensures: the server never holds the words, a watcher
  cannot read the message, and any change to the locked message itself
  is detected.  What can close the gap needs the decrypter to reach the
  reader once by a route that cannot be changed; options put to the
  owner the same day.
- **The cipher's speed**: the owner expects a 100 MB video in about 2
  seconds ("You must have built it wrong").  The measured 4.6 MiB/s is
  the textbook form, written for checking rather than speed; the
  decrypter needs the table-driven form, held to a test of at least
  50 MiB/s.
- **Speed of the hand-written cipher** (measured 2026-10-09, Node 24 on
  this machine, the skill's `rmail-seal.js`): 4.6 MiB/s.  A 9 GB file
  would take about half an hour of a desktop's time to decrypt in the
  page, longer on a phone.  The slow parts are known (GHASH done one bit
  at a time; AES one byte at a time) and table-driven versions are
  usually ten times faster or more; to be measured when built.
- **Found 2026-10-09, plain http changes two parts of the design**:
  browsers give a page their built-in decryption and their private file
  storage (the Origin Private File System, named under "Decisions") only
  on https or localhost.  So the decrypter carries its own AES-GCM
  *decryption* in plain JavaScript (as the skill's `rmail-seal.js`
  carries sealing, checked on a plain-http page in Firefox), and pieces
  wait in IndexedDB, which every page gets, rather than in private file
  storage.  Measured in headless Firefox 157 on a page served over plain
  http from 192.168.1.100: `isSecureContext` false, `crypto.subtle` and
  `navigator.storage` (so `getDirectory`) absent, `indexedDB` present and
  a binary write to it succeeded, `getRandomValues` present.
- **Folders.**  "Attachments & directories" shares a folder as a
  browsable listing with a `download.zip`; encrypted, the listing and
  the zip have to be built and decrypted another way.  Not yet designed.
- *(Answered 2026-10-04: encrypted, key in the link, no HTTPS — see
  "Decisions (2026-10-04)".  The question as it was asked:)*
  **Encryption.**  The owner asked whether the page can stay encrypted
  ("Could we use like, HTTPS or something?").  The browser reads the
  page in the clear over plain HTTP, the 2026-07-11 decision.  Options:
  HTTPS with a certificate (a real one needs a name that resolves to
  this machine, or an address certificate; a self-made one makes the
  browser warn every visitor); or the page holds only ciphertext and the
  key travels in the part of the link after `#`, which browsers never
  send — but the decrypting then needs JavaScript in the page, which
  this design forbids.  Asked 2026-10-04; the owner asked how the
  link-key way would work, explained the same day (the path names the
  message by its random words; the server sends one generic page and
  that message's ciphertext; the page's script reads the key from the
  link, decrypts with the browser's built-in AES-GCM, and shows the
  message, files decrypted in the browser and then saved, as MEGA does).
  Still to decide: plain HTTP, HTTPS, the link key, or HTTPS and the
  link key together — and, for the link key, whether "no JavaScript,
  ever" gives way for the one decrypting script.

## Suggested Implementation Steps

1. Answer "Still open" below.
2. Build in the order of the sections above: the trigger word, the HTTP
   listener on its own port, the URL words, the rendering, attachments and
   folders, lifetime, start-up and logging, the config keys — each tested
   against a page fetched with `curl`.

## Origin

Requested 2026-07-11 — "generate a URL anyone can open in a browser to
see a message/its files, no client needed," refined same day (plain
HTTP/no-certs, `to: url` trigger, config-driven port/word-count,
outbox-as-source-of-truth, themed rendering).

## Status

Open.
