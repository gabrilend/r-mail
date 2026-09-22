# #383 — Portable drives that run on more than one kind of processor

## Summary

A portable mailbox drive carries compiled programs — an interpreter and
four libraries — and a compiled program runs on one kind of processor.
A drive made on an x86-64 laptop does not run on an ARM single-board
computer, and the reverse.  The drive detects this and stops with an
explanation (#382), which is honest but not useful.

Build for several processors and put them all on the drive, with the
launcher choosing at startup.  Target laptops and single-board
computers: x86-64 and 64-bit ARM, with 32-bit of each as a later
question.

## Current behavior

One architecture, whichever the build machine was.  `run.sh` checks on
launch whether the drive's own interpreter can load the drive's own
libraries, and when it cannot it prints the drive's architecture and
the host's and stops.  Nothing is damaged and the mail is plain files
that read fine anywhere; the program is what will not run.

That check exists because the alternative was worse — the drive used to
recompile itself in place, which took minutes and wrote to somebody
else's machine.

## Intended behavior

A drive holds one build per supported processor.  `run.sh` asks the
host what it is and runs the matching one.  Plugged into something
nobody built for, it says so, names what it does have, and stops.

The mailbox itself is unchanged.  Mail, contacts, config, hooks and
state are text and are already architecture-independent; only
`source-code/` gains structure.

## The size question, measured before starting

Per architecture, because these are the compiled pieces:

| piece | size |
|---|---|
| `rmail_crypto.so` with OpenSSL linked in | 6.4 MB |
| the Lua interpreter | 316 KB |
| `socket/core.so` | 80 KB |
| Lua headers | 92 KB |
| `mime/core.so` | 24 KB |
| `rmail_inotify.so` | 20 KB |
| **total** | **~6.9 MB** |

Shared by all of them — `rmail.lua`, dkjson, LICENSE, hooks, the C
sources, the build note — about 340 KB.

So `N × 6.9 MB + 0.34 MB`.  Two architectures is 14 MB, four is 28 MB.

On the build machine instead: roughly 500 MB per cross toolchain from
this distribution's packages, and every one of the installer's eight
build phases needs a cross variant.

## Step 1, before any cross-compiling: make OpenSSL smaller

6.4 of the 6.9 MB is OpenSSL, and rmail uses two things from it:
AES-256-GCM and SHA-256.  The size is OpenSSL 3 routing even AES-GCM
through its provider machinery, so asking for two primitives pulls in
most of the library.

**This stays OpenSSL.**  Swapping in a smaller crypto library, or
moving the protocol to ChaCha20-Poly1305, would both shrink it further
and both were rejected: a well-known and audited library is worth more
to a program asking people to trust it with their mail than the
megabytes are.  Configuring OpenSSL to leave out what is unused is not
a swap — it is the same library, the same audits, the same name, built
smaller.

### Measured: it saves 18 percent, not an order of magnitude

Built OpenSSL 3.5.1 configured with everything rmail does not use
turned off — no TLS, no DTLS, no QUIC, no elliptic curves, no
Diffie-Hellman, no DSA, no engines, no legacy provider, no compression,
no deprecated interfaces — then linked `rmail_crypto.so` against it and
checked that encryption still round-trips.

| build | module size |
|---|---|
| system OpenSSL, static | 6.4 MB |
| minimal OpenSSL, static | **5.2 MB** |

An earlier estimate in this issue said a minimal build might reach
something near 530 KB.  That was wrong, and wrong in the direction that
would have wasted the effort: OpenSSL 3 routes AES-GCM through its
provider machinery, and the provider machinery is most of the bulk.
Turning off algorithms does not turn that off.

The order-of-magnitude saving was only ever available from the two
routes that were rejected — a different crypto library, or a different
cipher.  So the decision to keep OpenSSL costs roughly 4.7 MB per
architecture, and that is the real price of the trade rather than the
several hundred KB it first looked like.

**It is still worth doing** — 1.2 MB per architecture, about 5 MB
across four, for a build-flag change and no new dependency.  It is not
the thing that decides whether multi-architecture is affordable,
because multi-architecture is affordable either way:

| architectures | at 6.9 MB each | at 5.7 MB each |
|---|---|---|
| two | 14 MB | 12 MB |
| four | 28 MB | 23 MB |

## Proven: every piece cross-builds

Done before designing anything, because the whole issue rests on it.
With `cross-aarch64-linux-gnu` installed, each compiled component was
built for 64-bit ARM on this x86-64 machine and checked with `file` and
`readelf`:

| piece | result |
|---|---|
| `rmail_inotify.so` | ARM aarch64 shared object |
| Lua interpreter | ARM aarch64, needs only `libm` and `libc` |
| OpenSSL, minimal config | ARM aarch64 archive, 9.1 MB |
| `rmail_crypto.so`, OpenSSL linked in | ARM aarch64, **4.4 MB**, no libcrypto needed from a host |

The ARM crypto module is *smaller* than the x86-64 one — 4.4 MB against
5.2 MB — so an ARM payload lands near 4.8 MB and the two-architecture
drive is about 10.5 MB rather than the 12 MB estimated above.

Not yet built for ARM: luasocket's `socket/core.so` and `mime/core.so`.
Plain POSIX C with no external dependencies, and the lowest-risk items
in the set, but unproven is unproven.

Also confirmed here: building Lua without readline holds across the
toolchain.  The ARM interpreter names `libm`, `libc` and the ARM
dynamic linker and nothing else.

## Where the cross-building should live

Not in `install.sh`.  That script installs rmail on the machine it is
run on, and it is two thousand lines of doing that.  Teaching all eight
of its build phases to also target other processors would roughly
double it, in service of something only the drive generator ever wants.

A separate script that builds one architecture's payload, which the
drive generator calls once per architecture, keeps cross-compiling out
of the install path entirely and leaves it testable on its own.  The
installer stays the thing that sets up this machine.

## Suggested implementation steps

1. **Measure a minimal OpenSSL** — done, see above.  6.4 MB to 5.2 MB.
   Worth taking, not worth waiting for: the installer should grow a
   drive-oriented OpenSSL build using those flags, but nothing below
   depends on it.

2. **Name the architectures.**  x86-64 and aarch64 to begin with —
   laptops and single-board computers.  32-bit ARM and 32-bit x86 are
   a separate decision, and the cost table above says what they add.

3. **Write the payload builder** — split out as #385,
   `generate-portable-mailbox.sh`, because it is worth having even for
   a single architecture: it is what would have prevented the readline
   and host-OpenSSL problems instead of patching them after the fact.
   Everything below assumes it exists.

4. **Lay the drive out per architecture.**  `source-code/x86-64/`,
   `source-code/aarch64/`, and the architecture-independent files
   beside them rather than inside either.

5. **Teach the launcher to choose.**  `uname -m`, mapped to a
   directory.  When there is no match, print what the drive holds and
   stop — the same shape as the current message, with a list.

6. **Verify each build before it ships.**  The generator already proves
   the drive's Lua can load the drive's libraries before handing it
   over.  It can only do that for the architecture it is running on;
   for the others it can check that the files are of the expected
   machine type, which is weaker but not nothing.

7. **Say what it is.**  The drive README and the generator's summary
   should name which processors the drive was built for, so somebody
   holding it can tell without plugging it in.

## Decisions

**OpenSSL stays.**  See step 1.  The argument for a smaller library is
size; the argument against is that rmail has one user today and wants
more, and "it uses OpenSSL" is worth more than several megabytes when
asking a stranger to trust a mail program.

**Linux only.**  Settled in #382: rmail needs POSIX sockets, inotify,
fork and exec, and a filesystem, and a target without an operating
system needs its own implementation rather than another build of this
one.  macOS is a separate question — see #384.

## Related

- #382 — put the program on the drive in the first place, and added the
  check that refuses to run on the wrong processor.
- #339 — the portable drive itself.
- #384 — macOS, which is the same question about a different operating
  system rather than a different processor.

## Open questions

- 32-bit targets at all?  About 5.7 MB each once step 1 lands.  The
  question is whether anybody plugs an rmail drive into 32-bit
  hardware, not whether the drive can hold it.
- Installing a cross toolchain is about 500 MB on the build machine and
  needs root.  Is that acceptable on the machine that makes drives, or
  should cross-building happen somewhere else and the outputs be
  carried in?
- Should the installer be able to cross-compile for a machine, or only
  the drive generator?  Cross-installing rmail onto another machine's
  filesystem is a different job from making a drive, and may not be
  wanted at all.

## Status

Open.  No steps started.
