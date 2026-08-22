# #376 — Let a daemon tell its peers what code it is running

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

## Current state

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

**Distribution of built trees is already planned.** #339 (portable
mailbox drive) copies the source tree *and prebuilt libs* onto a USB
drive; #361 (portable installer drive) ships the installer.  Those are
the moments a modified daemon actually changes hands, so whatever
identity stamp this issue introduces has to survive being copied onto a
drive by those generators, where no git checkout is present.

## Proposed mechanism

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

The install script already writes config early (#340, completed), so it
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
#329) should show, per contact, what that contact's daemon claims to be
— and should visibly mark a contact whose declared revision and computed
digest disagree, or who answers with no identity at all.  Design the
copy so an ordinary user reads it as "is this person's mail program
normal?" rather than as a license notice.

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
- `scripts/make-mailbox-drive.sh` and #339 / #361 — the copy paths the
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
   generated by #339 has no checkout.  Does the generator stamp the
   revision it built from, and if so what stops that value from being
   copied forward onto a later, modified tree?

8. **What should a client do when the check fails?**  Refuse to sync,
   warn loudly, or quietly mark the contact?  Refusing turns a license
   feature into a denial-of-service against people with unusual builds.

## Status

Open.  No code written.
