---
name: rmail-integration
description: How another program or project should send to, or receive from, an rmail mailbox — writing outbox files from a script, a feedback box on a project's HTML documentation that reaches a project-specific rmail inbox (the owner's CLAUDE.md asks for one on every interactive docs page), a small local relay that turns a web page's text into an outbox file, a page a real contact uses with their own token, and hook scripts that act on what arrives. Covers the owner's rules (tokens are never published in a web page; a message a program writes is written once and never touched again; refuse and log, never quietly repair), which pattern fits which system, the exact file and wire formats, and the browser rules that decide what a page may reach. Use when a project wants to "send this to my rmail", "add a feedback box", "make a project inbox", "have the docs send feedback", "drop it in ~/mail/outbox", "notify me by rmail when X", or asks how a web page or script can talk to rmail. Carried in the r-mail repository; copy the whole folder into another project's .claude/skills/ to use it there.
---

# rmail integration

How other systems should use rmail: what to write, where, and why each
rule exists.  The owner's CLAUDE.md wins wherever it and this file
disagree.  This file is carried by the r-mail repository
(`.claude/skills/rmail-integration/`); another project copies the folder
into its own `.claude/skills/`.

## rmail in the terms this file uses

- **Mailbox** — a folder: `config` (this mailbox's `name` and `port`),
  `contacts` (one block of lines per contact), `inbox/`, `outbox/`,
  `attachments/`, `.state/` (the daemon's own records, JSON).  One
  daemon serves one mailbox: `run-rmail.sh <mailbox>/config`.  A machine
  can hold several mailboxes, each on its own port.
- **Message** — a plain text file.  In `outbox/` it is waiting to be sent
  (or already sent and still "live", see below); in `inbox/` it arrived.
  The file name is the subject.
- **Contact** — a name in `contacts` with an address and a **token**:
  `alice.ip = 203.0.113.1`, `alice.port = 8025`,
  `alice.token = "long-random-words"`.  The address may be a host name
  (`feedback.ip = wow.ritzmenardi.com`).  The token is a password both
  sides write down; the 32-byte lock key is the SHA-256 of it.
- **Sealing** — every message travels as one frame: a 4-byte big-endian
  length, a 12-byte random nonce, then the AES-256-GCM ciphertext with its
  16-byte tag.  Inside is an HTTP-style request (`POST /deliver`, headers,
  JSON body).  The receiver tries each contact's key until one opens the
  frame; whichever opens it is who sent it.  No name travels in the
  clear.  Full detail: `docs/protocol.md` in the r-mail repository.

## The owner's rules

1. **Contact tokens are never published in a web page** — not in the
   source, not in a script the page loads, not in a file served beside
   it.  A token in a page is a token anyone who opens the page holds.
2. **A message a program writes is written once and never touched
   again.**  An outbox file is a *living message*: if its text changes,
   the change is sent to every recipient as an edit; if it is deleted,
   every recipient's copy is deleted.  A program that rewrites or tidies
   its outbox files edits or erases what people already received.
3. **Deletes come only from people.**  The patterns here only ever create
   messages.  Nothing in them sends a delete.
4. **Refuse and log; never quietly repair.**  Input that fails a check is
   refused with a reason and a log line, not cleaned up and passed on.
5. **Generating is kept apart from viewing.**  The code that builds a page
   with a feedback box, the code that receives what the box sends, and
   the code that writes the outbox file are separate pieces with plain
   files between them.

## Which pattern fits

| The system is…                                     | Use                                          |
|----------------------------------------------------|----------------------------------------------|
| a script or program on the same machine as a mailbox | **A. Write an outbox file**                 |
| a web page on this machine (a docs feedback box)    | **B. A local relay**, which then does A      |
| a page a real contact uses, typing their own token | **C. Sealed in the browser**                 |
| something that should act when mail arrives         | **D. Hook scripts**                          |
| strangers on the internet, from a public https page | not supported now — see "What does not work" |

The docs feedback box CLAUDE.md asks for is pattern **B**.

## A. Write an outbox file

The simplest and most reliable way in: the daemon already watches its
outbox and does all the sealing, addressing, retrying and backing off.

The file:

```
to: feedback

page: protocol.html
kind: something is unclear

The second diagram has its arrows backwards.
```

- One `to:` line per recipient, each a contact name from that mailbox's
  `contacts`.  Blank lines are allowed inside the header.  `attach:
  <path>` lines send files (each needs the recipient's consent first).
- Everything after the header is the message.  The recipient sees only
  the message, not the `to:` lines.
- The file name is the subject.  On arrival the receiver turns it into a
  file name: folder parts and leading dots are taken off, control
  characters and slashes become `_`, spaces become `-`.

How to write it safely:

- **A name nothing else will ever use.**  Two messages under one name are
  one message edited (rule 2).  Put the time and something random in it:
  `feedback-protocol-20261008T143012Z-7f3a`.
- **Appear all at once.**  The daemon is told the moment the outbox
  changes and may read a file that is still being written, then send the
  rest later as an edit.  Write to a hidden name in the same folder —
  the daemon skips names that start with a dot — and rename it to its
  real name when complete: `outbox/.feedback-….partial` →
  `outbox/feedback-…`.  A rename within one folder is one step; a rename
  across file systems is a copy and is not.
- **Then leave it alone.**  When every recipient has deleted their copy,
  the daemon removes the outbox file itself.

## B. A local relay, for web pages on this machine

A web page cannot write files, and under rule 1 it cannot seal a message.
So a small program on this machine — the relay — accepts plain text from
the page and does pattern A with it.  The token stays in the mailbox's
`contacts`, where the daemon reads it; the page never sees it.

Why the relay needs care: **any website open in the browser can send a
POST to `http://127.0.0.1:<port>/`.**  Browsers allow "simple" requests
(POST with `Content-Type: text/plain`) to any address without asking it
first; the page just cannot read the answer unless the relay allows it.
(Newer Chrome asks the viewer before a public site reaches `localhost`;
other browsers and older versions do not, so the relay must not count
on it.)  So a careless relay lets every website the owner visits send mail in the
owner's name.  The checks below are what stop that.

What the relay must do, in order:

1. **Listen on `127.0.0.1` only**, never `0.0.0.0` (which is every
   network the machine is on).  Pick a port nothing else uses.
2. **Check `Host`** is exactly `127.0.0.1:<port>` or `localhost:<port>`.
   This defeats DNS rebinding: a hostile site that points its own name
   at 127.0.0.1 still sends its own name in `Host`.
3. **Check `Origin` against a fixed list** — the address the docs are
   served from, e.g. `http://127.0.0.1:8090`.  Browsers set `Origin` and
   a page cannot change it.  **Never accept `Origin: null`.**  Pages
   opened as files (`file://…`) send `null`, but so does a sandboxed
   frame on *any* website, so `null` cannot tell your docs from a
   stranger's page.  Serve the docs from a small local web server
   instead of opening them as files.
4. **Take only a POST with `Content-Type: text/plain`**, body at most a
   few KB (say 16 KB), and refuse everything else.  `text/plain` keeps
   the request "simple", so the browser sends it without a separate
   permission check first.
5. **Read the body as a fixed shape** and check every part:
   - the page name must be one of the pages the docs builder actually
     produced (read its list of pages; do not trust the page's word);
   - checkbox lines (`kind: something is unclear`) must be keys and
     values from a fixed list;
   - the free text has a length cap, and control characters other than
     line end and tab are refused.
   Anything that fails is refused with a reason (rule 4).
6. **The recipient comes from the relay's own settings**, never from the
   request.  A page that could choose the recipient could mail anyone in
   `contacts`.
7. **Write the outbox file as in pattern A**, into the outbox of the
   mailbox that holds the recipient contact.
8. **Answer** `200` with the file name, adding
   `Access-Control-Allow-Origin: <that same allowed origin>` so the page
   may read the answer and show "sent"; refusals get `4xx` with the
   reason.  Log every refusal, with the origin it came from.
9. Optionally limit how many messages a minute it accepts.

The page side (made by the docs builder, kept apart from the relay):
a text box, the fixed checkboxes, the page's own name, and a `fetch` to
the relay with `method: "POST"`, `mode: "cors"`, `Content-Type:
text/plain`.  It shows what the relay answered — including a refusal and
its reason — rather than assuming success.

Where the message goes — the **project inbox** — is a contact in the
relay's mailbox.  Two shapes:

- **One mailbox per project**: a mailbox folder inside the project
  (git-ignored — `contacts` holds tokens), with its own port and
  service; the owner's main mailbox has it as a contact and the relay
  writes into the main mailbox's outbox addressed to it.
- **One feedback mailbox for everything**: one contact (say `feedback`,
  whose address may be a host name like `wow.ritzmenardi.com`), with the
  project's name in the subject.

New mailboxes and services come from r-mail's own installer
(`scripts/install.sh`), not by hand; it picks a free port and writes the
service file.  Tokens: long and random, different for every pair.

A relay is written in Lua (luajit-compatible) per the house rules;
r-mail carries luasocket and dkjson in its `libs/`.  Logs go to the
project's `tmp/shared-memory/`.

## C. Sealed in the browser, with the viewer's own token

For a page used by someone who *is* a contact: they type their own token
into the page (or the page keeps it in that browser's storage).  The
token is theirs and never part of the page's files, so rule 1 holds.
The page seals the message itself and sends it straight to the
mailbox's port.

`rmail-seal.js` beside this file does it with the browser's built-in
WebCrypto, and `r-mail/scripts/test-browser-sealer.sh` checks that very
file against a real daemon.  What happens on the wire:

- A page cannot send bare bytes; the browser always writes a request
  line and headers first.  So the frame goes as the body of a POST, with
  `Content-Length` = 4 + the frame's length.  rmail tells this apart
  from a bare frame by the first byte: a frame length starts 0x00–0x04,
  a web method starts with a capital letter.  It unwraps the POST and
  reads the frame like any other; anything that is neither is closed
  without a word.
- The sealed answer comes back as the body of a web reply.  rmail sends
  no `Access-Control-Allow-Origin`, so a page must use `mode: "no-cors"`
  and learns only that an answer came, not what it said.
- The browser's own headers (`User-Agent`, and `Origin`: the address of
  the page) travel in plain text beside the sealed message.

## D. Hook scripts, for acting on what arrives

Set in the mailbox's `config`; a path that is not absolute is taken from
the folder holding the config.

| Hook             | Runs when                       | Gets                                  |
|------------------|---------------------------------|---------------------------------------|
| `on_receive_raw` | before a message is written     | sender, subject, body; its output **replaces** the body |
| `on_receive`     | after a message is written      | sender, subject, path to the file (runs in the background) |
| `on_update`      | the author edited a message     | see r-mail's scripting tutorial       |
| `on_delete`      | the *other* side deleted one    | the other party's name                |
| `on_send`        | a message was sent              | see r-mail's scripting tutorial       |
| `on_package`     | an attachment was saved         | sender, file name, path               |

- `on_receive_raw` **cannot refuse**: empty output keeps the original
  body.  To refuse, check in `on_receive` and move the file out of
  `inbox/` into a refused folder, with a log line.  Moving it out counts
  as the recipient deleting it, so the sender's outbox loses that `to:`
  line — for relay-sent feedback, that sender is the owner's own
  mailbox.
- Contacts may carry extra fields (`feedback.project = "r-mail"`) that
  rmail stores and ignores; hooks may read them.

## What does not work, and why

- **Strangers on the internet, from a public https page.**  Browsers do
  not let an https page send to a plain `http://` address other than
  the same machine, and rmail has not spoken TLS since it moved its lock
  into each frame.  Chrome also asks the viewer's permission before a
  public site may reach `localhost` or the home network.  And a stranger
  holds no token, which rule 1 keeps that way.  Pages on this machine,
  served from `localhost`, are what these patterns are for.
- **Opening the docs as files** with a relay: `Origin: null`, see B.3.
- **Reading or deleting the inbox from a page**: only the owner's own
  devices (contacts marked `own = true`) may use rmail's `/api/` paths,
  and they hold every token.  Not for web pages.

## Checklist for a new integration

1. Which pattern (table above)?  Write the choice and the reason into the
   project's issue file.
2. The recipient contact exists in the sending mailbox's `contacts`, and
   the receiving mailbox has the sender with the same token.
3. Outbox files: unique names, hidden-then-renamed, never touched again.
4. A relay: 127.0.0.1 only; `Host` and `Origin` checked; never `null`;
   fixed recipient; fixed shapes; refusals answered and logged.
5. A test that sends one message through the whole path and finds it in
   the receiving inbox, and one that is refused for each check.
6. Any mailbox folder inside a project is git-ignored.

## Open questions

- Is the project inbox one mailbox per project, or one shared `feedback`
  mailbox with the project in the subject?  (Both are described in B; the
  owner has not chosen.)
- The relay is described here, not built.  Should r-mail carry one
  reference relay, tested like `rmail-seal.js`, so each project does not
  write its own?
