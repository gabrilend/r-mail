# #382 — The mailbox is the installation

## Summary

A mailbox is currently a directory of mail plus a set of pointers to
things kept elsewhere: its config in `~/.config/rmail/`, its hook
scripts in the git checkout, its program in the git checkout.  Move all
three inside the mailbox, so a mailbox is a complete, self-contained
installation that happens to sit at a path.

This makes the installed mailbox and the portable-drive mailbox the
same kind of thing.  Today they are two layouts maintained in parallel
by two different generators, and every feature has to be built twice.

## Current behavior

### Where a mailbox's parts live

| part | installed mailbox | portable drive |
|---|---|---|
| mail | `<mailbox>/inbox`, `outbox`, `contacts`, `.state` | same |
| config | `~/.config/rmail/config-<path-slug>`, with a symlink at `<mailbox>/config` | `<mailbox>/config`, a real file |
| hooks | the checkout's `scripts/hooks/`, by absolute path | `<mailbox>/scripts/`, by relative path |
| program | the checkout, by absolute path in the service file | `<drive>/source-code/`, found relative to the launcher |

### What that costs

**Two mailboxes share one set of hook scripts.**  Every installed
mailbox's config points at the same six files in the checkout.  Editing
the receive hook to change what one mailbox does changes what every
mailbox on the machine does, silently.  On this machine both mailboxes
point at the same six scripts right now.

**The config filename is a mangled path.**  Because every mailbox's
config lives in one shared directory, the filename has to carry the
mailbox path to stay unique: `config-home-ritz-notes-rmail`.  That slug
is a transform, the transform got reimplemented in the daemon, the two
copies had to agree forever, and #381 is the issue about what happened
when they did not.  Put the file in the mailbox and the filesystem
supplies uniqueness for nothing.

**A missing port silently becomes 8025.**  The daemon reads
`config.port or 8025`.  The installer never writes 8025 — it generates a
random port in 50000–65000 — so this can only fire when a config is
unreadable or the key is misspelled.  8025 is a real mailbox's port on
this machine, so the failure mode is two daemons on one port, the second
dying on a bare Lua assertion from `socket.bind`.

**Port collisions are checked by reading other mailboxes' configs.**
The installer scans `~/.config/rmail/` and compares the `port` line of
every sibling.  This requires each mailbox to know about the others,
which is the wrong relationship, and it only detects collisions with
*rmail*: a port already taken by any other program on the machine is
assigned without comment.

**A daemon's complaints go only to a log** nobody is reading.

## Intended behavior

A mailbox directory contains everything that mailbox needs:

```
<mailbox>/
  inbox/            received mail
  outbox/           mail to send
  attachments/      received attachments
  contacts          address book and shared secrets
  config            this mailbox's settings — the source of truth
  hooks/            this mailbox's own hook scripts, edited in place
  program-files/    the daemon, its libraries, and its launcher
  .state/           sync tracking
```

Nothing outside it is consulted.  `~/.config/rmail/` does not exist.
No mailbox reads another mailbox's anything.

The config is the source of truth and is not overridden by anything —
no environment variables, no service-file precedence.  A service file
does exactly one thing: name a mailbox's config and launcher.

The installer becomes a factory: it builds mailboxes and generates
service files, and is not otherwise involved in running one.  A mailbox
outlives the checkout that made it.

A portable drive is then an ordinary mailbox that happens to be on
removable media.  The drive generator's remaining job is placing a
launcher at the drive root and writing the drive's README.

## Suggested implementation steps

Ordered so each step leaves a working installer and a working daemon.

1. **A missing port is an error.**  Delete the `or 8025`.  Stop with a
   message naming the config file and the missing key.  Small, and
   independent of everything below.

2. **IP-change notices default to off.**  A mailbox that moves — and
   under this issue every mailbox can move — would otherwise announce
   itself to every contact on arrival.  The drive already sets this
   false for exactly that reason; make it the default everywhere and
   drop the drive's special case.

3. **Each mailbox gets its own hooks.**  Copy the default hook scripts
   into `<mailbox>/hooks/` at install time and reference them
   relatively.  Relative to the *config file's directory*, matching the
   rule `mail` already follows, so hook paths do not depend on which
   directory a service manager happened to pick.  The drive's
   `<mailbox>/scripts/` becomes `<mailbox>/hooks/` so there is one name.

4. ~~**Each mailbox gets its own program.**~~  **Withdrawn — see "The
   program does not go in the mailbox" below.**  It was built, run for
   an afternoon, and taken back out.  An installed mailbox holds no
   program; the service runs the one checkout's daemon.  A mailbox on
   removable media carries a trimmed copy, because there is no checkout
   on the far end to run.

5. **The config moves into the mailbox.**  `<mailbox>/config` stops
   being a symlink and becomes the file itself.  The slug transform,
   the config directory, and the migration-from-old-location code all
   go.  `mail = .` in every config, or drop the key entirely and let
   the config's own directory be the mailbox.

6. **The installer stops reading sibling configs.**  Check the chosen
   port against what is actually listening on the machine.  This sees
   more than the sibling scan did — any program's port, not just
   rmail's — and less: a mailbox that exists but is not running is
   invisible.  That is the honest division, because the installer can
   only ever guess and the daemon is the thing that finds out.

7. **The daemon reports its own problems as mail.**  A failure on the
   inbound path writes a message into the inbox; a failure on the
   outbound path writes one into the outbox.  The daemon already does
   the outbound half for the router-insecurity warning, which writes a
   file into the outbox with `to:` lines; this generalises it and adds
   the inbound direction.  First case: a port that will not bind.

8. **Service files name the mailbox's own launcher and config**, not
   the checkout's.  This is what makes a mailbox outlive its checkout.

9. ~~**Refresh a mailbox's program files.**~~  **Deleted with step 4.**
   It existed only to undo the staleness that step 4 created: once a
   mailbox carried its own daemon, updating the checkout updated
   nothing, and something had to go round replacing the copies.  With
   one checkout serving every mailbox on the machine, updating the
   checkout is the update, and there is nothing to refresh.

   A drive still holds a copy and can still fall behind the checkout it
   came from.  Regenerating the drive is how that is fixed, which is
   the same operation as making it in the first place.

10. **Straggler paths.**  `validate-router-settings.sh` reads the
    pre-slug `~/.config/rmail/config`, which has been wrong since the
    slug landed.  `generate-docs.sh` locates a mailbox by scanning the
    config directory.  Both need the new layout.

## Migration

Three mailboxes' worth of state exists on this machine and none of it
may be lost.  Before anything moves, inbox and outbox contents are
copied to a directory under `/tmp`, and restored from there once the
new layout is in place and verified.

The running daemons read their config once at startup, so a config that
moves under a running daemon is not noticed until it restarts — which
means the move is safe to stage and the restart is the cutover.

Service files are root-owned and the installer never escalates
privileges, so the two installed service files have to be replaced by
hand.  The installer generates them; the operator installs them.  That
is a deliberate constraint, not an oversight, and it makes the service
replacement an explicit step in this migration rather than something
that happens invisibly.

Leftovers to be reported and not deleted: `~/.config/rmail/config`
(pre-slug, still naming `~/mail`), and the three unenabled service
directories `rmail`, `rmail-home-ritz-mail` and
`rmail-home-ritz-notes-rmail`.  Removing a service directory is the
operator's call.

## Related

- #381 — made the config the daemon's single argument and deleted the
  path-to-slug guess.  This issue removes the slug itself, which is
  what made the guess possible.  It also partly un-builds #381's
  sibling-config scanning: that scan was the right answer while configs
  shared a directory, and stops being the right answer here.
- #343, #344 — introduced and defended the slug.  Both are superseded
  by step 5: the problem they solved does not exist once the file lives
  in the mailbox.
- #339 — the portable-drive layout, which is the layout this issue
  adopts everywhere.
- #376 — a daemon offering the source it runs.  A mailbox that carries
  its own program has a local answer to that question; the two should
  agree on what counts as the corresponding source.
- #200 — shared-device sync, the case that makes a self-contained
  mailbox worth more than a tidy one.

## The program does not go in the mailbox

Step 4 gave every mailbox its own copy of the daemon under
`program-files/`.  That was built and then withdrawn the same day, and
the reasoning is worth keeping because the mistake was a reasonable one.

**What it was supposed to buy.**  A mailbox that survives its checkout
being moved, updated or deleted, and service files that do not point
into a git clone.

**What it actually bought.**  Those things, and a copy of the program
per mailbox that nothing keeps current.  Twenty minutes after the two
mailboxes on this machine were migrated, the checkout had moved on and
both were running a daemon that no longer matched it — the staleness
arrived immediately and unprompted, before anyone had gone looking for
it.  Step 9 existed to paper over this and would have had to keep
existing forever.

**Where the reasoning went wrong.**  The problem was never that the
program sat outside the mailbox.  It was that the program sat in a git
checkout, which moves.  Installing it somewhere stable fixes that
without duplicating anything, and the fix was mistaken for the
requirement.

**The portability was partly illusory.**  A copied `program-files/`
carries compiled `.so` files that may not load under a different host's
Lua.  The drive already knows this: its launcher probes whether the
copied libraries load and rebuilds them when they do not.  An installed
mailbox carried the same fragile copy with nothing that coped.

**The drive was pointing at the answer.**  It never adopted
`program-files/` — it keeps one program at `source-code/` serving the
mailbox beside it.  That exception got a comment justifying it rather
than the notice it deserved: it was not an exception, it was the
general rule.  One program, many mailboxes, and the thing that joins
them is the service file on a machine and the launcher on a drive.

**Where the program lives now.**

| | one program | the mailboxes | what joins them |
|---|---|---|---|
| machine | the checkout | `~/mail`, `~/notes/rmail`, … | the service file |
| drive | `<mailbox>/source-code/` | the mailbox beside it | `run.sh` |

A drive carries a trimmed copy: the daemon, its launcher, its own Lua
interpreter, its libraries, the C sources those are built from, a
fifteen-line build note, and LICENSE.  Not the Android client, the
docs, the issues, or the transcripts.

### What a drive asks of a host, and what it stopped asking

**The interpreter is required, not preferred.**  A drive that relies on
the host having a usable Lua fails on the host you needed rather than
the hosts you tried — and fails as an undefined symbol from inside
`require`, because a host's Lua may be a different version than these
libraries were built against.  The generator refuses to build a drive
without one, and the launcher uses the drive's and never the host's.

**Lua is built without readline.**  readline exists for Lua's
interactive prompt, which nothing here runs, and linking it makes the
interpreter depend on libreadline and libncursesw as well as libc and
libm.  Those two are exactly what a minimal host is liable not to have.
Measured: four dependencies down to two, both present on every Linux.

Fully static would be better and is not possible — the daemon loads its
libraries as shared objects at runtime, and a statically linked
executable cannot `dlopen` anything.

**The crypto module carries its own OpenSSL.**  The checkout's copy
borrows `libcrypto` from the machine it was built on, which is right on
a normal install and a dependency on a stranger for a drive: OpenSSL 3
and OpenSSL 1.1 export different symbols, so a drive built against one
and plugged into a host with the other fails at load.  That is the gap
between a current distribution and a long-term-support one, not an
exotic case.

The generator relinks it against `libcrypto.a`.  Measured: 18 KB to
6.4 MB, because OpenSSL 3 routes even AES-GCM through its provider
machinery and "only what is referenced" turns out to be most of the
library.  A flash drive has 6 MB; a host that cannot load the module
does not.  After this the module needs only libc.

The build-time halves of the interpreter — `liblua.a`, `luac`, the man
pages — stop travelling too.  Nothing runs them.  The headers stay,
because BUILD-NOTES.txt tells the reader they can rebuild what is in
their hand and that should be true.

**A compiled interpreter is not portable across architectures**, and no
amount of bundling changes that.  An x86-64 build does not run on ARM.
So the launcher checks on startup and stops with a message naming the
drive's architecture and the host's, where it used to spend several
minutes recompiling itself on a machine somebody had just plugged it
into.  That rebuild was a fallback wearing a convenience's clothes: it
hid the mismatch, and it wrote to a drive that might be someone else's.

To make that message honest, the generator runs the same check before
handing the drive over.  A drive that leaves the factory is known to
work somewhere, so a later failure really is the host.

**`install.sh` and `scripts/hooks/` stopped travelling.**  The
installer was there only to do that rebuilding, and to stand in as the
build instructions the licence wants beside a shipped binary.  The
second job is real and is now done by `BUILD-NOTES.txt`: the recipe is
two `cc` invocations and a `make linux`, which is fifteen lines rather
than two thousand.  `scripts/hooks/` was a second copy of the six files
already sitting in the mailbox's own `hooks/`, carried only so the
installer could seed a mailbox that was already seeded.

**What this gives up.**  A mailbox directory copied to a machine with
no rmail on it will not run.  Put it on a drive, or copy it to a
machine that has rmail.  Given the library probe above, that capability
was never as solid as it looked.

**And the Android client stops travelling on drives.**  A drive is your
mailbox made portable, not a way of handing rmail to somebody new.  The
phone app comes from the checkout, where its build script and setup
guide already are.  The README section added earlier pointing drive
recipients at `source-code/clients/android` is removed with it.

## Decisions

**The config file is the source of truth, not a gesture at it.**  No
environment variable and no service file overrides any value in it.
The alternative considered was letting the service file supply
machine-specific settings, which was rejected: it makes the config a
default rather than an answer, and it means the same mailbox behaves
differently depending on how it was started.

**Machine-specific settings live in the mailbox's config anyway.**
Port, library paths and port-forwarding are properties of an
arrangement rather than of a mailbox, but splitting them into a second
file buys nothing for a mailbox on local disk and nothing for a mailbox
on a drive, where both files travel together regardless.  One file.

**Mailboxes do not know about each other.**  Any check that requires
reading another mailbox's files is the wrong check.  Where that removes
information, the missing information is obtained from the system
instead, or found out at the moment it matters and reported then.

## Answered: the `mail` key does not survive

Removed.  A config always sits in the mailbox it serves, so the
directory the file is in already says which mailbox it is.  A line
saying the same thing can only repeat it or contradict it, and a fact
that cannot be stated wrongly needs no validation and no error message
for getting it wrong.

Old configs keep the line harmlessly — the daemon does not read it.
`migrate-mailbox-layout.sh` strips it, and warns first if it named a
directory other than the one it is sitting in, because that is the one
case where somebody may have meant something by it.

## Answered: how a daemon gets behind its checkout

The phrasing that raised this was wrong.  A mailbox's copy is never
older than the checkout that made it *at the time it was made* — it is
a snapshot of that moment.  What happens afterwards is that the
**checkout** moves on: a pull, or an edit to the daemon, and the
mailbox keeps the snapshot.

So the question is not how a copy ages.  It is how anybody finds out
that the thing running is no longer the thing in the tree.  That is
exactly what #376's build identity is for — a stamp naming the source a
running daemon was built from.  With one, a mailbox can be asked what
it is and the answer compared with the checkout.  Without one, the only
way to know is to remember.

This issue does not need to solve it.  It needs to not pretend the
problem is somewhere else.

## Scope: Linux only

Decided rather than assumed.  rmail needs POSIX sockets, inotify, fork
and exec for hooks, and a filesystem for the mailbox.  Those are kernel
services, not library code that can be linked in, so a target without
an operating system cannot be reached by a different build of this
program — it needs its own implementation of the protocol.  Projects
doing that will supply their own answers for the OS-level pieces.  This
issue and this program are Linux.

## What a multi-architecture drive would cost

Measured on this machine, for when someone picks this up.

Per architecture, because these are compiled:

| piece | size |
|---|---|
| `rmail_crypto.so` with OpenSSL linked in | 6.4 MB |
| the Lua interpreter | 316 KB |
| `socket/core.so` | 80 KB |
| `mime/core.so` | 24 KB |
| `rmail_inotify.so` | 20 KB |
| Lua headers | 92 KB |
| **per architecture** | **~6.9 MB** |

Shared by all of them — `rmail.lua`, dkjson, LICENSE, the hooks, the C
sources and the build note — comes to about 340 KB.

So a drive that runs anywhere costs `N × 6.9 MB + 0.34 MB`: about 14 MB
for x86-64 and 64-bit ARM, 28 MB for four architectures including
32-bit. Nothing, on a flash drive.

The cost is on the build machine instead: roughly 500 MB per cross
toolchain from this distribution's packages, and each of install.sh's
eight build phases would need a cross variant.

**The lever nobody has pulled.**  6.4 of those 6.9 MB is OpenSSL, and
rmail uses exactly two things from it: AES-256-GCM and SHA-256.  The
size comes from OpenSSL 3 routing even AES-GCM through its provider
machinery, so linking two primitives drags in most of the library.

Without it, a per-architecture payload is about 530 KB and a
four-architecture drive is around 2.5 MB.  Three ways at that, cheapest
first: configure OpenSSL to exclude what is unused; swap it for a small
embedded-focused library such as BearSSL, around 100 KB; or move the
protocol to ChaCha20-Poly1305, where compact public-domain
implementations are a few tens of KB.  The last is a protocol change
and the others are not.

This also decides the shape of any future static build.  A statically
linked binary cannot load `.so` modules — verified: the module opens
and then fails on `undefined symbol: lua_pushlstring`, because a static
link leaves the interpreter's API out of the dynamic symbol table, and
`-Wl,-E` does not rescue it.  The way through is to compile the modules
into a custom Lua binary and register them in `package.preload`, so
nothing is ever loaded at runtime.  Paired with musl, that is one file
with no dependencies at all.

Worth being precise about musl, because the usual warning is about the
other case: a *dynamically* linked musl binary names
`/lib/ld-musl-x86_64.so.1` as its ELF interpreter, and a glibc system
does not have that file, so it will not start.  A *statically* linked
one names no interpreter at all — verified with `readelf` — so there is
nothing for a glibc system to be missing.  Static musl runs anywhere of
its architecture.

## Open questions

- Does `program-files/` carry enough to satisfy the license's
  corresponding-source requirement, or only enough to run?  See the
  section below, which narrows it but does not close it.

## What `program-files/` should carry

It currently holds the daemon, its launcher, `libs/`, the two C
sources, LICENSE, and a locally compiled Lua if there is one — 1.7 MB,
of which 1.2 MB is the interpreter.

Carrying the rest of the checkout is not a size question.  Everything
except the compiled OpenSSL tree comes to about 2.5 MB, and that tree
is build-time only: the crypto library links against the system
OpenSSL, verified with `ldd`.  So the question is what belongs, not
what fits.

**Missing, and arguably required.**  `scripts/install.sh` is the script
that compiles the two `.so` files in `libs/`.  A license that asks for
the source of a binary generally means the build instructions too, so
shipping `rmail_crypto.c` without the thing that turns it into
`rmail_crypto.so` may be half an answer.

**Worth carrying on its own merits.**  `docs/`, `helpers/`, `README.md`
— together a few hundred KB — would make a mailbox self-describing to
whoever it reaches, which is the same instinct as putting the config
and the hooks inside it.

**One thing that should not travel.**  `llm-transcripts/` is the record
of building this, four files of conversation.  A mailbox is the thing
that goes on a removable drive and gets handed to people; a development
diary is not part of the program and has no business riding along.

**Not needed here, but the question exposed something else.**
`clients/android/` is a separate program that talks to this one over a
socket, not corresponding source for the daemon, and it is already
reachable by everyone who could want it: on your own machine it is in
the checkout, and a portable drive rsyncs the whole checkout to
`source-code/`, so the app source, `compile-android.sh` and the
rendered setup guide are all on every drive already.

What was missing was any way to *find out*.  The drive's README had no
mention of Android or a phone anywhere in it, so somebody handed a
drive held the complete means to build the phone client and no reason
to think so.  Adding 568 KB per mailbox would not have fixed that; a
paragraph in the README did.

The general shape is worth keeping: a thing being present is not the
same as a thing being reachable, and for anything handed to another
person the README is the only index they have.

`issues/` and `notes/` are the project's workings rather than the
program's.

What is left open is only the license half, and it needs #376 to settle
what a daemon should be able to hand over when asked.

## Status

In progress.

Steps 1 through 8 and step 10 are done.  Both mailboxes on this machine
have been migrated and verified, and their service files are generated
and waiting to be installed by hand.

### Steps done

1. A missing port is an error — done.
2. IP-change notices default to off — done.
3. Each mailbox gets its own hooks — done, including the drive
   generator, whose `<mailbox>/scripts/` became `<mailbox>/hooks/` so
   there is one name for the thing.
4. Each mailbox gets its own program — **built, then withdrawn.** An
   installed mailbox holds no program; a drive mailbox carries a
   trimmed copy at `<mailbox>/source-code/`.
5. The config moves into the mailbox — done.
6. The installer stops reading sibling configs — done; it asks the
   system what is listening instead.
7. The daemon reports its own problems as mail — the mechanism exists
   and the first case, a port that will not bind, uses it.  Only that
   one case reports so far.
8. Service files name the checkout's daemon and the mailbox's config —
   done.  This was briefly the mailbox's own launcher, and is not.
9. Refresh a mailbox's program files — **deleted along with step 4**.
   Nothing to refresh: one checkout serves every mailbox, so updating
   the checkout is the update.
10. Straggler paths — done.  Both scripts now take a mailbox.
11. The `mail` key is gone — done.  The mailbox is the config's own
    directory and cannot be written down anywhere.
12. The port is claimed before the router is probed — done.

### Claiming the port first

The daemon used to probe the router for UPnP and NAT-PMP, and request
a port forward, all before binding its own port.  On a router that
ignores those probes that is about eight seconds, so a mailbox whose
port was already taken spent eight seconds negotiating for a port it
was then going to fail to claim, and only then said so.

Binding moved above the router work.  A collision is now reported in
under a second, and the two steps are in the order that makes sense on
their own terms: a port forward is a request to send traffic somewhere,
and it is worth making only once you are the one holding the other end.

### What the install-time identity check became

Step 6 removed it rather than reimplementing it, and that is a decision
rather than an omission.  The danger was never two configs holding the
same string; it was a `to:` line that resolves both as this mailbox's
own identity and as a contact, which one mailbox can walk into with no
sibling anywhere by adding a contact named after itself.  #381 made the
daemon refuse exactly that, naming both readings, at the moment it
arises.  Checking the real condition where it happens beats checking a
proxy for it at install time, and it needs no mailbox to read another's
files.

### Found while doing this

The installer could not complete on this machine at all.  Two lines in
the zip and unzip build phases used `${VAR//./}`, which bash understands
and the `/bin/sh` in the shebang does not — dash stops there with "Bad
substitution", mid-phase, after the downloads.  Fixed in place; it has
nothing to do with this issue beyond having blocked the first test of
it.

### Verification

`scripts/test-mailbox-selection.sh` — 24 cases, all passing, covering
the port rules and the bind-failure notice added here alongside #381's
cases.

The new layout was built from scratch by the installer into a throwaway
mailbox, then run: it serves itself, resolves its own relative hooks
from an unrelated working directory, and self-delivers.  An instrumented
hook inside that mailbox ran while the checkout's shared copies stayed
untouched, which is the per-mailbox-hooks claim tested directly.

Both migrated mailboxes were verified by checksum against the checkout
and by running a copy of one of them in isolation.  Their services were
then repointed at their own program copies and restarted, and both
answer the health check under their own names on their own ports.  The
old config directory has been removed.

A drive was regenerated and run: same mailbox layout as an installed
one, and an instrumented hook inside it fired.

### The Android client needs no change

Checked rather than assumed, because a layout change is exactly the
kind of thing that breaks a client quietly.

The app holds its own settings on the phone — host, port and token per
mailbox — and reaches the daemon only over the network API: sync,
contacts, attachments, log, myaddress, the two upload calls, file
downloads, and the health check.  None of those carry a config path, a
hook path or a program location, so none of them can notice where those
moved to.

Two earlier decisions are why the surface is that narrow.  #308
rejected giving the phone a desktop-synced config.  #309 fixed as
non-negotiable that phone hooks and desktop hooks are separate and
never shared.  Both of those keep the phone out of the desktop's
filesystem entirely, which is what makes this change invisible to it.
