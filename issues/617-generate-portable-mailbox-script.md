# #617 — `generate-portable-mailbox.sh`: build a portable mailbox rather than copy one

## Summary

A portable mailbox drive is currently assembled by copying whatever the
checkout happens to have lying in `libs/` and `deps/`.  Those artefacts
were built by `install.sh` for the machine it ran on, with whatever
options suited a local install, and the drive inherits all of it —
including choices that are right for a local install and wrong for a
drive.

Build the portable payload on purpose instead, with a script shaped
like `install.sh`: numbered phases, each producing one thing, each
skipping work already done, each saying what it found or made.

## Current behavior

`make-mailbox-drive.sh` creates the mailbox, writes the config and the
launcher, and copies the program in.  The copying is the problem.  What
it copies is whatever `install.sh` left behind:

- **An interpreter built for a local install.**  Until recently that
  meant one linked against readline and ncurses, which a drive has no
  use for and which a host may not have.  The generator now warns about
  this and tells you to re-run `install.sh --force`, which is a
  workaround for not controlling the build.
- **Libraries built against this machine's OpenSSL.**  The generator
  now relinks the crypto module statically to fix that, which is the
  right outcome reached by patching up somebody else's build rather
  than doing the right build.
- **One architecture**, because that is what the checkout has.

Each of those was solved where it surfaced.  The pattern underneath is
that the drive generator is downstream of a build it does not control,
and keeps discovering that the build was not for it.

## Intended behavior

One script that builds a portable mailbox's program from source, for
one named architecture, with the options a portable thing wants:

- Lua without readline, so the interpreter needs only libc and libm.
- OpenSSL configured down to what rmail uses, linked into the crypto
  module so no host OpenSSL is required.
- luasocket and the two rmail libraries against that Lua.
- Nothing else.  No Android client, no docs, no issues, no transcripts.

It reports what it built and what that costs, the way `install.sh`
reports what it compiled.  Run twice for two architectures.

`make-mailbox-drive.sh` then places a mailbox and one or more built
payloads onto a drive, and stops being in the business of compiling
anything.

## Why it should look like install.sh

Because the job is the same job and the shape already works.
`install.sh` is a sequence of phases that each check whether their
output exists, build it if not, and say which happened.  That is
exactly right for this: building four things from source, any of which
may already be done from a previous run, on a machine where any of them
may fail for local reasons.

Worth copying specifically:

- **Numbered phases with a one-line banner each.**  A build that takes
  several minutes should say where it is.
- **Skip what exists, and say so.**  `found in libs/…` is as useful an
  output as `compiled`.
- **Licence harvesting.**  `install.sh` keeps each dependency's licence
  file out of its unpacked source; a payload that ships binaries wants
  the same, and `scripts/test-license-harvest.sh` already tests that
  routine by lifting it out of `install.sh`.
- **Refusing clearly.**  Naming the missing package rather than failing
  in the middle of a compile.

Worth *not* copying: the prompts.  This builds an artefact, it does not
set up somebody's mail, so it takes arguments and no questions.

## Suggested implementation steps

1. **Take a target and an output directory.**  Default the target to
   the machine's own architecture, so the common case is one argument
   or none.  Refuse a target whose toolchain is not installed, naming
   the package.

2. **Phase: Lua.**  Fetch, build with `make linux` — deliberately not
   `linux-readline` — install into the output tree.  Cross-building
   needs `CC` set to the toolchain's compiler and nothing else; this is
   proven, see #619.

3. **Phase: OpenSSL.**  Configure with rmail's two primitives and
   little else; the working flag set is recorded in #619.  Static only.
   This is the long phase — several minutes — and should say so before
   it starts rather than appearing to hang.

4. **Phase: luasocket.**  Against the Lua from step 2.

5. **Phase: the two rmail libraries.**  `rmail_crypto.c` linked against
   the static OpenSSL from step 3, then verified to need no libcrypto
   from a host — that check is cheap and the failure is silent
   otherwise.  `rmail_inotify.c` for Linux targets; `rmail_kqueue.c`
   for macOS ones, if #620 ever gets a Mac.

6. **Phase: assemble and verify.**  Lay out the payload the way the
   drive expects, write `BUILD-NOTES.txt`, and — when the target is
   this machine's own architecture — run the built interpreter against
   the built libraries to prove they load.  For other architectures,
   check the file types match what was asked for, which is weaker but
   catches the toolchain silently falling back to the host compiler.

7. **Move the copying out of `make-mailbox-drive.sh`.**  It should
   place a payload, not build or relink one.  The static-crypto relink
   and the readline warning both live there today and both belong here
   instead.

## Decisions

**Separate from `install.sh`, not a mode of it.**  `install.sh` sets up
rmail on the machine it runs on, and does it in two thousand lines.
Adding a target-architecture dimension to all of its phases would
roughly double that, in service of something only drives want.  See
#619, where this was argued in full.

**No prompts.**  Arguments only.  It produces a build artefact; there
is no user whose preferences it needs.

## Related

- #619 — several architectures on one drive.  This script is that
  issue's step 3, pulled out because it is worth having even for one
  architecture: it is the thing that would have prevented the readline
  and the host-OpenSSL problems rather than patching them afterwards.
- #616, #102 — the portable drive and what it carries.
- #620 — macOS, which would add a target to step 5 rather than change
  the shape of anything.
- `scripts/test-license-harvest.sh` — the pattern of lifting a routine
  out of `install.sh` rather than copying it, which this script may
  want for the licence-harvesting phase.

## Open questions

- Does `make-mailbox-drive.sh` survive as a separate script, or does
  this absorb it?  Two scripts is honest — one builds a program, one
  writes a drive — but "generate a portable mailbox" is a sentence that
  describes both, and the names would need to stop overlapping.
- Where do built payloads live between building and being written to a
  drive?  A directory in the checkout is simplest and wants a
  `.gitignore` entry; RAM is per the project convention but these are
  tens of megabytes and survive reboots badly.
- Should it be able to build a payload for a *machine* rather than a
  drive — a self-contained rmail that could be unpacked anywhere?
  Nothing needs that today, and saying no keeps the output shaped for
  exactly one consumer.

## Status

Built 2026-11-05: steps 1 to 7.  `scripts/generate-portable-mailbox.sh`
builds one architecture's payload in seven numbered phases (target,
sources, Lua, OpenSSL, luasocket, the two rmail libraries, assemble and
verify), each skipping what a previous run left and saying so.
`make-mailbox-drive.sh` now places a payload and compiles nothing: the
static relink, the `libcrypto.a` search and the readline warning are
gone from it, because the payload is built right in the first place.

Not yet proven here: a build from the real Lua and luasocket sources.
The machine this was written on could fetch OpenSSL's release tarball
but not lua.org or GitHub's source archives, so
`scripts/test-portable-payload.sh` builds from stand-in archives that
record how they were driven (`make linux` and never `linux-readline`,
Configure's flags, the compiler) and install the system's Lua and
libcrypto.  The real OpenSSL 3.5.1 can be put through the same test
with `RMAIL_TEST_OPENSSL=<path to openssl-3.5.1.tar.gz>`.  An aarch64
payload needs `gcc-aarch64-linux-gnu`, which was not installed; the
refusal that names it is tested.

## Decisions (2026-11-05)

- **Two scripts.**  The generator builds a program; the drive maker
  writes a mailbox and places a program on it.  The names stopped
  overlapping by what each says it makes: a *payload* is the built
  program, a *drive* is where it goes.  #619 already has the drive
  maker calling the payload builder once per architecture, and this
  keeps that shape.
- **Payloads live in `deps/portable/<arch>/`**, beside the build tree
  that produced them (`deps/portable/<arch>/build/`), and downloaded
  archives in `deps/sources/`.  `deps/` is already ignored, so no new
  `.gitignore` entry.  Not RAM: tens of megabytes that take minutes to
  rebuild, which is the case the project's RAM convention does not cover.
- **No payload for a machine.**  Nothing needs one, and it would give
  the output two consumers.  The payload is shaped as a drive's
  `source-code/` and nothing else.
- **The drive maker builds one if none is given.**  `--payload DIR`
  places that one; with none, it uses this machine's own
  (`deps/portable/<arch>/payload`) and runs the generator first if it
  is not there, so the common case stays one command.  One payload per
  drive until #619 lays drives out per architecture.
- **OpenSSL 3.5.1 with #619's flags**, not install.sh's pinned 3.2.1:
  #619 measured the flag set on 3.5.1 and checked that encryption still
  round-trips, and a payload is a separate build from a local install.
  Lua 5.4.7 and luasocket 3.1.0 as install.sh pins them.
- **Licences are harvested by install.sh's own routine**, lifted out
  of it with sed the way `scripts/test-license-harvest.sh` does, and
  the build refuses to finish a payload missing any of the three.
- **The load check needs no network.**  On a host-architecture build
  the generator runs the payload's Lua: it loads `socket.core`,
  `mime.core`, `rmail_crypto` and `rmail_inotify`, and round-trips
  AES-256-GCM.  For another architecture it checks every binary's ELF
  machine with `readelf` (not `file`, which is not on every build
  machine), and for either it checks with `readelf`'s NEEDED list that
  the crypto module needs no `libcrypto` and the interpreter needs
  nothing past libc, libm and the loader.
- **A drive built from another architecture's payload is not refused.**
  The drive maker cannot run that Lua, says so and names what it was
  built for; the generator already checked its file types.
- **Not built:** `rmail_kqueue.c` for macOS (#620), several payloads on
  one drive (#619 steps 4 and 5).
- Test: `scripts/test-portable-payload.sh`.
