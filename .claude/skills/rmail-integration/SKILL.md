---
name: rmail-integration
description: How a website, a documentation page, or another program sends to an rmail mailbox — the general method for every website that needs a feedback box or contact form reaching an rmail inbox (the owner's CLAUDE.md asks for one on every interactive docs page). The page seals each message itself in JavaScript and POSTs it straight to the mailbox; the website is one contact in the receiving mailbox, which accepts only a plain message from it. Covers setting up a website contact, the delivery script, what the receiving mailbox must refuse, reaching a mailbox from a public https site, checking what arrives with hooks, and the simpler route for a program on the same machine (writing an outbox file). Use when a project wants to "add a feedback box", "send this to my rmail", "make a project inbox", "have the website/docs send messages to rmail", "notify me by rmail when X", or asks how a web page or script can talk to rmail. Carried in the r-mail repository; copy the whole folder into another project's .claude/skills/ to use it there.
---

# rmail integration

The general method for getting messages from websites and programs into
an rmail mailbox.  The owner has several websites that need it, so
everything here is written to be repeated per site.  The owner's
CLAUDE.md wins wherever it and this file disagree.  This file is carried
by the r-mail repository (`.claude/skills/rmail-integration/`); another
project copies the folder into its own `.claude/skills/`.

## rmail in the terms this file uses

- **Mailbox** — a folder: `config` (this mailbox's `name` and `port`),
  `contacts`, `inbox/`, `outbox/`, `attachments/`, `.state/` (the
  daemon's own records).  One daemon serves one mailbox and listens on
  its port on every network interface.
- **Message** — a plain text file.  The file name is the subject.
- **Contact** — a name in `contacts` with a **token**, a password both
  sides hold: `blog.token = "long-random-words"`.  A contact rmail sends
  to also has an address (`.ip`, `.port`).
- **Sealing** — every message travels as one frame: a 4-byte big-endian
  length, a 12-byte random nonce, then AES-256-GCM ciphertext with its
  16-byte tag, locked with the SHA-256 of the token.  Inside is an
  HTTP-style request (`POST /deliver`, a JSON body).  The receiver tries
  each contact's key until one opens the frame; that contact is the
  sender.  No name travels in the clear.  Encryption is just math: a
  page can do it in plain JavaScript as well as rmail does.
- **Web wrapping** — a browser cannot send bare bytes; it always writes a
  request line and headers first.  So a page sends the frame as the body
  of a plain web POST.  rmail tells the two apart by the first byte (a
  frame length starts 0x00–0x04, a web method with a capital letter),
  unwraps the POST, and reads the frame like any other; any other opening
  is closed without a word.  Detail: `docs/protocol.md`, "A frame sent
  from a web page".

## The method: the website is a contact, and the page seals

```
 visitor's browser                         the owner's mailbox
 ┌──────────────────────────┐              ┌───────────────────────────┐
 │ page: text box, checkboxes│              │ contacts:                 │
 │ delivery script:          │  web POST    │   blog.token  = "…"       │
 │   website token           │ ───────────► │   blog.listen = true      │
 │   seal → frame (plain JS) │  body=frame  │ → plain message accepted  │
 └──────────────────────────┘              │ → anything else refused   │
                                           │ inbox/<subject>           │
                                           │ on_receive hook checks it │
                                           └───────────────────────────┘
```

1. **One contact per website** in the receiving mailbox, with its own
   token.  The website *is* the contact.  Every visitor sends as it.
2. **The token lives in the site's delivery script**, the code that seals
   and POSTs — not written into the page's text.  Whoever loads the site
   can still read any script their browser runs, so the token is treated
   as known to anyone.  That is safe only because of step 3.
3. **The website contact may send a plain message and nothing else.**
   The receiving mailbox refuses everything else from it: deletes, edits
   (an edit rewrites an earlier message by its id, so one visitor could
   rewrite another's), attachments, address changes, every other request
   — only rmail's unauthenticated health check (`GET /`) stays open, as
   it does for everyone.  And rmail never sends anything to a website
   contact: no announcements, no deletion notices, no retries.  The
   restriction belongs to the *contact*, not to the web wrapping: the
   same token works in a bare frame sent by any program, so refusing only
   what arrives through a browser would protect nothing.
4. **The page seals each message itself** with `rmail-seal.js` (beside
   this file) and POSTs it to the mailbox.
5. **A receive hook checks what arrived**, because anyone can send it.

### Status: step 3 is not built yet

rmail issue **#420** ("a token-only contact is listened to, never sent
to") is the receiving side of step 3: a contact line such as
`blog.listen = true` (the word is still open), one gate where every
decrypted request is dispatched, and a 403 with a log line for
everything but a plain message.  **Until #420 is built, a website token
can do whatever a person's token can** — delete or rewrite messages that
came through it, send attachments, change its own address — and rmail
will try to send to whatever address the last visitor announced.  Do not
put a website live against a mailbox before #420 is completed.

## Setting up one website

In the receiving mailbox:

```
// the blog's feedback box (#420: may only send plain messages)
blog.token  = "blog-a-long-random-string-used-for-nothing-else"
blog.listen = true
```

- A token of its own, never shared with a person or another site.  If it
  is abused, change it in both places (contacts and the delivery script)
  and only that site is affected.
- No `ip` or `port`: nothing is ever sent to a website.
- Which mailbox receives: the owner's main one, or one per project or
  site (its own folder, port and service, made by r-mail's
  `scripts/install.sh`).  A mailbox folder inside a project is
  git-ignored — `contacts` holds tokens.

On the site: the box (a text field, fixed checkboxes, the page's own
name as the subject) is built by the site's page generator; the delivery
script is separate from it (rule: generating kept apart from sending).

## The delivery script

`rmail-seal.js` is loaded with a plain `<script src>` (not a module: a
page opened as a file cannot load modules) and offers
`RMAIL_SEAL.sendMessage(url, token, subject, text)`: build `POST
/deliver` with JSON `{type: "message", subject, body, message_id}`, seal
it, and POST the frame with `Content-Type: text/plain`.

**It does the encryption arithmetic itself, on every page.**  Browsers
have AES-GCM and SHA-256 built in (`crypto.subtle`), and
`crypto.randomUUID`, but give them only to *secure* pages — https, this
machine, a local file.  A page served over plain http from a server gets
neither: `crypto.subtle` is simply undefined.  So the file carries
SHA-256, AES-256 and GCM written out in plain JavaScript (copied from the
W client project's `docs-seal.js`, which offered it), and takes only
random numbers from the browser (`crypto.getRandomValues`, which every
page gets).  One way of sealing on every page, not a built-in lock with a
hand-written one behind it.

`r-mail/scripts/test-browser-sealer.sh` checks that very file: the
standards' published answers (SHA-256 of "abc"; AES-256-GCM test cases
13 and 14); byte-for-byte agreement with Node's built-in cipher for
lengths 0 to 4097; delivery to a real daemon from Node (recorded as from
the right contact, multi-byte letters whole, a wrong token gets nothing);
and delivery from **Firefox on a page served over plain http** from the
machine's home-network address, where Firefox reports the page insecure
and the built-in lock absent.

Facts it depends on:

- `Content-Length` inside the sealed request counts **bytes**, not
  characters (`TextEncoder`, not `string.length`).
- AES-GCM's 16-byte tag goes after the ciphertext: the order rmail
  expects.
- A fresh random `message_id` per message (made from
  `getRandomValues`).  The id is how rmail knows a re-sent frame is the
  same message: a replayed frame changes nothing.
- The answer: rmail sends the sealed answer back as the body of a web
  reply but no `Access-Control-Allow-Origin` header, so a browser page
  must use `mode: "no-cors"` and learns only that an answer came, not
  whether delivery succeeded.  A network failure, or a mailbox that
  refused the frame and closed, does reject the promise.
- The browser's own headers (`User-Agent`, `Origin` — the page's
  address) travel in plain text beside the sealed message.

## Reaching the mailbox

rmail speaks plain TCP on its port, with no TLS, and the message is
sealed either way.  Which address a page may send to depends on how the
page itself is served:

- **A site served over plain `http://`** (the owner's choice for the W
  client's docs: "no https, not just local") — the page POSTs straight
  to `http://<mailbox host>:<port>/`.  Nothing in between.  This is the
  case the hand-written arithmetic exists for, and the one the Firefox
  test exercises.
- **A page on the same machine** (`http://localhost…`, or a file) — the
  same, to `http://127.0.0.1:<port>/`.
- **A site served over `https://`** — a browser blocks an https page from
  sending to a plain `http://` address (mixed content), except
  `localhost`.  Such a site needs an https web server in front of the
  mailbox's port (a reverse proxy: e.g. `https://example.org/feedback` →
  the mailbox's port).  The proxy passes the POST through, and rmail reads
  the web wrapping as above; the path in the request line is ignored.
  The proxy must pass the body unchanged with its `Content-Length`
  (rmail refuses a declared length that does not match the frame).
  **Not yet tested.**
- Newer Chrome asks the visitor's permission before a public site reaches
  `localhost` or the home network; a mailbox at a public address is not
  affected.

## Checking what arrives

Anyone can send through a website contact, so its messages are a
stranger's bytes.  rmail already takes folder parts, leading dots and
control characters out of the subject before it becomes a file name.
The rest is a hook's job, set in the mailbox's `config` (a relative path
is taken from the config's folder):

| Hook             | Runs                         | Gets                                   |
|------------------|------------------------------|----------------------------------------|
| `on_receive_raw` | before the message is written | sender, subject, body; its output **replaces** the body |
| `on_receive`     | after it is written (background) | sender, subject, path to the file  |

- `on_receive_raw` cannot refuse: empty output keeps the original body.
  To refuse, check in `on_receive` and move the file out of `inbox/` into
  a refused folder, with a log line (rule: refuse and log, never quietly
  repair).
- Check against fixed lists: checkbox lines (`kind: something is
  unclear`) only from a fixed set of keys and values; the page name only
  from the site's real list of pages; the free text capped in length.
- A hook gets the body as one program argument, which Linux caps at 128
  KiB; a longer body never starts the hook.  Keep website messages small
  (the box can cap its own text); the limit rmail should put on a
  website contact is open in #420.

## A program on the same machine: write an outbox file

No sealing, no contact of its own: the daemon already watches its outbox
and does all the sealing, addressing and retrying.

```
to: feedback

page: protocol.html
kind: something is unclear

The second diagram has its arrows backwards.
```

- `to:` names a contact in that mailbox.  The file name is the subject.
- **Write once, never touch again.**  An outbox file is a living message:
  a changed file is sent to every recipient as an edit, a deleted one
  deletes their copies.  Give each message a name nothing else will use
  (time plus something random).
- **Appear all at once.**  Write it under a hidden name in the same
  folder (the daemon skips names starting with a dot) and rename it into
  place when complete; otherwise the daemon may send half and then the
  rest as an edit.

## Checklist for a new website

1. #420 is built in the receiving rmail (until then: do not go live).
2. A contact for this site alone, marked listen-only, no address.
3. The delivery script uses `rmail-seal.js` with that contact's token.
4. The page can reach the mailbox: plain http straight to its port, or —
   for a site served over https only — an https proxy in front, tested.
5. A receive hook that checks every part and refuses with a log line.
6. A test that sends one message through the whole path and finds it in
   the inbox, and one per refusal: a delete, an edit and an attachment
   with the website token are each refused.

## Open questions

- #420's: the word for the mark (`listen`, `submit_only`, …); whether a
  contact with a token and no address is listen-only without it; the
  size limit for a website contact's messages.
- Should rmail add `Access-Control-Allow-Origin` to its web replies, so
  a page can open the sealed answer and tell the visitor "delivered" (the
  answer is sealed, so the header reveals nothing)?
- The https proxy path (for sites served over https only) is described,
  not tested.
