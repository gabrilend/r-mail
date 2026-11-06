# #615 — Let a daemon tell its peers what code it is running

## Summary

A running rmail daemon cannot currently answer the question "what
source code are you?"  There is no build identity in the daemon, no way
for a peer to ask, and no way for the daemon to point at the source it
was built from.

Give the daemon a **build identity** (a stamp naming the exact source it
is running) and a **source offer** (a way for the people it talks to to
go get that source).

## Why

Two separate needs land on the same mechanism.

**The trust need.**  rmail's whole premise is that you hand a shared
secret to a person you know and then exchange plaintext-on-disk messages
with them.  Everything after that assumes the daemon on the other end
behaves the way the published daemon behaves.  Nothing today lets you
check that.  A correspondent whose daemon silently logs every message,
or forwards a copy elsewhere, is indistinguishable on the wire from one
running a stock build.  A build identity does not *prove* honesty — a
liar can stamp anything — but it converts "I have no idea what you are
running" into "you claim to be running X, and here is where X's source
lives, so I can go read it."  That is the difference between no answer
and a checkable answer.

**The license need.**  rmail is under AGPL-3.0-or-later (see `LICENSE`).
Section 13 of that license says that if you modify the program and other
people interact with your modified version remotely over a network, you
must prominently offer those people a way to receive the corresponding
source of *your* version, from a network server, at no charge.  rmail is
exactly that shape: a daemon peers reach over TCP.  Nothing in the daemon
offers anything today, so a modified daemon has no route to compliance
even if its operator wants one.

These are the same feature.  Build the mechanism once and it serves both.

## Current Behavior

**No build identity exists.**  Searching the daemon for a version
constant finds only an unrelated UUID version-nibble and some comments.
The daemon does not know what it is.

**Some of the mechanism is already built, and works.**  The request
handler already serves two things that are close relatives of a source
offer:

- `GET /deps` and `GET /deps/<name>` return `DEPS_REGISTRY`
  (`rmail.lua:148`) — the table of dependency names with min, max,
  default version and a description.
- `GET /install-script` reads `scripts/install.sh` off disk, computes
  its SHA-256 by shelling out to `sha256sum`, and returns the script
  body with the digest in an `X-SHA256` header.

That second one is the pattern this issue extends: read a real file off
the running tree, hash it, hand it over.  It already proves the daemon
can serve its own on-disk artifacts to a peer and let them verify
what they got.

**The channel is authenticated and encrypted by default.**  In
`handle_request` (`rmail.lua:4910`), a connection either opens with the
four bytes `GET ` — the plaintext health check — or with a length-prefixed
encrypted frame.  Encrypted frames are trial-decrypted against every
contact key (`trial_decrypt`), so reaching any real endpoint requires
already holding a shared secret.  `is_own_device` further gates the
`/api/` surface to the operator's own clients.

**One unauthenticated surface already exists.**  The plaintext health
check answers any TCP connector with `{ok = true, name = <my_name>}`.
So the daemon is *already* identifiable to an unauthenticated scanner,
and already leaks the operator's chosen name.  This matters to the
design below: the argument "an unauthenticated source offer would make
the daemon fingerprintable" is weaker than it first appears, because
the health check does that today.

**Distribution of built trees is already planned.** #616 (portable
mailbox drive) copies the source tree *and prebuilt libs* onto a USB
drive; #618 (portable installer drive) ships the installer.  Those are
the moments a modified daemon actually changes hands, so whatever
identity stamp this issue introduces has to survive being copied onto a
drive by those generators, where no git checkout is present.

## Intended Behavior

Three pieces, in dependency order.

### 1. A build stamp the daemon can read

The daemon needs a string naming its own source.  Two candidate
sources, and they are not exclusive:

- **Declared revision** — written at install time by
  `scripts/install.sh` into a generated file the daemon reads at
  startup, the way `rmail-run` and the service files are already
  generated.  Content: git describe / commit hash when a checkout is
  present, otherwise whatever the drive generator stamped in.
- **Computed digest** — hash the files the daemon actually loaded
  (`rmail.lua`, `rmail_crypto.c`/`.so`, `rmail_inotify.c`/`.so`, the
  contents of `libs/`) and fold them into one digest.  This is the
  honest one: it describes the code that is really running rather than
  what a file claims.  The existing `/install-script` handler already
  demonstrates the shell-out-to-`sha256sum` approach.

The declared revision is a *claim*; the computed digest is *evidence*.
Serve both and let the peer notice when they disagree.

### 2. A place to point at the source

A new configuration setting — `source_url` — naming a network location
where the corresponding source of *this* daemon can be fetched.  It
defaults to the upstream project location.  An operator running a
modified daemon is required by section 13 to change it to point at their
own modifications; the config file comment should say so plainly, since
the config file is where that operator will actually be looking.

The install script already writes config early (#607, completed), so it
is the natural place to seed this.

### 3. A way to ask

A new read-only endpoint alongside the existing `/deps` and
`/install-script` handlers, returning the declared revision, the
computed digest, the `source_url`, and the license identifier.

Whether it *also* appears in the unauthenticated health-check response
is the main open question below.

### 4. Surfacing it where a human sees it

An endpoint nobody looks at is not a "prominent offer."  The thin
clients (`clients/android`, `clients/linux`, and the desktop viewer of
#711) should show, per contact, what that contact's daemon claims to be
— and should visibly mark a contact whose declared revision and computed
digest disagree, or who answers with no identity at all.  Design the
copy so an ordinary user reads it as "is this person's mail program
normal?" rather than as a license notice.

## Suggested Implementation Steps

1. The build stamp (mechanism 1); then where the source is (2); then the
   request that asks for both (3); then where a person sees it (4) — each
   a step with its own test, in that order, once the open questions are
   answered.

## Relevant code and files

- `handle_request` (`rmail.lua:4910`) — connection auth, health check,
  path dispatch.
- The `/deps`, `/deps/<name>` and `/install-script` branches inside it —
  the closest existing pattern to copy.
- `DEPS_REGISTRY` (`rmail.lua:148`) — the shape a static served table
  takes today.
- `script_dir` (`rmail.lua:166`) — how the daemon locates its own tree.
- `scripts/install.sh` — generates `rmail-run`, `rmail.service`,
  `rmail.nix`, `rmail-init`; would generate the stamp.
- `scripts/make-mailbox-drive.sh` and #616 / #618 — the copy paths the
  stamp has to survive.
- `LICENSE` — the obligation this satisfies, including the hook-script
  exception, which matters for question 5 below.

## Open questions

1. **Which channel carries the offer?**  The authenticated endpoint
   reaches contacts and own devices over an encrypted link and fits the
   existing design exactly.  The plaintext health check reaches
   *everyone*, which is closer to what "prominently offer all users"
   asks for, but hands a scanner a second identifying field.  Given the
   health check already answers with the operator's name, is the
   marginal privacy cost real, or already paid?

2. **Is a peer a "user interacting remotely"?**  A contact clearly is.
   Is an anonymous TCP connector that only ever gets a health check?
   The stricter reading argues for the plaintext channel; the narrower
   one is satisfied by the authenticated endpoint.

3. **What exactly is the corresponding source?**  The daemon plus the
   two C extensions is the obvious core.  Do the four client programs
   count?  They are part of the licensed work, but a peer talking to a
   daemon is not interacting with the operator's Android build.

4. **Serve a URL, or serve the bytes?**  A URL is simple but dead if
   the operator's host is offline or the link rots.  Serving actual
   source is possible — `/install-script` already does it for one file —
   but tarring the running tree risks handing over generated files that
   carry machine-specific paths (`rmail-run`, `rmail.service`,
   `rmail.nix` are all generated and all gitignored) and anything else
   the operator happened to leave in the directory.  If we ever serve
   bytes, it must be an explicit allowlist of source files, never a
   directory sweep.

5. **Should hook scripts be excluded from the digest?**  The license
   exempts hook scripts, and they are user property that may be
   proprietary.  A digest that covered them would both overreach and
   leak the existence of the operator's private tooling.  Confirm the
   digest covers only rmail's own files.

6. **Should an unmodified daemon advertise too?**  Section 13 binds
   modified versions.  But if only modified daemons answer, then
   answering becomes a signal in itself, and silence becomes the safe
   choice for the dishonest.  Uniform advertisement removes that
   incentive — every daemon answers, and the interesting case is the one
   whose answer does not check out.

7. **How does the stamp get produced with no git present?**  A drive
   generated by #616 has no checkout.  Does the generator stamp the
   revision it built from, and if so what stops that value from being
   copied forward onto a later, modified tree?

8. **What should a client do when the check fails?**  Refuse to sync,
   warn loudly, or quietly mark the contact?  Refusing turns a license
   feature into a denial-of-service against people with unusual builds.

## Decisions (2026-11-06)

Taken while building steps 1-3, so the work could go ahead; each can be
reversed.  Not legal advice: the licence readings below are the plain
reading of section 13, and the owner may want a lawyer's.

1. **Which channel: the authenticated one only.**  The premise of the
   question is out of date: the plaintext health check no longer names
   the mailbox.  #106 (completed 2026-10-04) dropped the name, on the
   owner's words "We shouldn't enable that", and it now answers
   `{"ok":true}` and nothing else.  Putting a revision or digest there
   would hand a scanner what #106 took away, and more: a digest pins the
   exact build, so a scanner could pick out unpatched ones.  So
   `GET /source` is a sealed request, open to every contact and to the
   owner's own devices; the health check is unchanged, and the test
   checks it stays so.
2. **A peer that only gets the health check is not a user interacting
   with the program.**  It can learn that something listens, and nothing
   else: it cannot send or receive mail.  Everyone who can exchange mail
   with the daemon holds a key, and every key holder can ask.  Listen-only
   contacts (#420, a website's door) stay refused, as for every request
   but a plain message; the website's own pages are where such a visitor
   would be offered the source, and that is not built (see below).
3. **The corresponding source is the whole repository**, which is what
   `source_url` points at.  The *digest* is narrower: rmail's own Lua
   (`rmail.lua`, `libs/dkjson.lua`, `libs/zip-*.lua`), the code that runs
   as it is read.  The compiled libraries are not in it: their bytes
   differ by compiler and machine, so a digest over them could never be
   compared with the published source.  The C sources are not in it
   either, because a drive's launcher runs from a copy that does not
   carry them; a `.so` rebuilt from changed C is therefore not detected,
   and would need reproducible builds to be.  The clients are not in it:
   a peer talks to the daemon, not to the owner's phone.
4. **A URL, not the bytes.**  `source_url` in the config, the project by
   default.  Serving the tree would need an allowlist and an answer to
   the size of a frame; nothing asked for it yet.
5. **Hook scripts are not in the digest.**  Confirmed: the list is fixed
   and names only rmail's own files.
6. **Every daemon answers**, changed or not, so answering is no signal
   and silence no refuge.
7. **The stamp without git.**  `scripts/build-stamp.sh` writes
   `build-stamp` beside `rmail.lua`: the revision (`git describe --always
   --dirty`, only when the folder is a checkout's own top, so a drive kept
   inside some other repository is not stamped with its commit), the
   digest of the files at that moment, and what stamped it.  install.sh
   stamps the checkout on every run, before it restarts the mailboxes;
   `generate-portable-mailbox.sh` stamps a payload with the revision of
   the checkout it copied from.  What stops a stamp being carried onto a
   changed tree: it records the digest, and the daemon compares.  A tree
   edited after stamping answers "changed since stamped"; re-stamping
   such a tree with no git writes "unknown, changed since <revision>"
   rather than keeping the old claim.  No time is in the stamp, so two
   kinds of machine built from one checkout carry the same one (#619's
   drive maker refuses payloads that differ outside their compiled
   parts).
8. **When the check fails, mark quietly; never refuse.**  For the step 4
   that is not built yet: a contact whose answer is "changed since
   stamped", "no stamp", or nothing is shown as such, and mail goes on.
   Refusing would turn a licence feature into a way to cut off people
   with their own builds.  The daemon itself logs the one case it can
   tell is a changed program with `source_url` still naming the project,
   since that is the operator the licence speaks to.

## What was built (2026-11-06)

Steps 1-3, on top of #617 and #619 (the drive generator and the drive
layout the stamp has to travel through):

- `scripts/build-stamp.sh` — writes the stamp, or prints a tree's digest
  with `--digest`.
- `rmail.lua` — the `identity` table: the digest worked out once at
  start, the stamp read, a log line saying which source this is, and
  `GET /source`.
- The `source_url` setting; install.sh writes it into a new config, with
  a comment saying what the licence asks of a changed program.
- `install.sh` stamps the checkout; `generate-portable-mailbox.sh` stamps
  each payload; the drive's launchers copy the stamp into the copy they
  run from.
- `scripts/test-build-identity.sh`; `scripts/test-portable-payload.sh`
  checks the payload's stamp and that a drive carries it.

Once #713 (the version number) is in, the answer could also carry
`RMAIL_VERSION`; it is a hand-raised label, not a name for the exact
source, so nothing here waits on it.

## Left

- Step 4: a daemon asking each contact's `/source` and keeping the
  answer where the clients can show it, and the clients (Linux, the
  #711 viewer, Android) showing it per contact, marked as decision 8
  says.
- An offer of the source on a website's pages (#714/#715), for visitors
  who reach a mailbox only through one.
- The owner's view on decisions 1-3, which read the licence.

## Status

In progress: steps 1-3 built (2026-11-06); step 4 left.
