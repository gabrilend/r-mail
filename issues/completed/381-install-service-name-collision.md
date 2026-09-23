# #381 — Install script: every mailbox generates the same service name

> Filed as #377 and renumbered to #381.  Another machine had already
> published its own #377 (per-contact sync timers) before this one was
> pushed, so this is the copy that moved — the same way the
> capability-URL issue moved from #376 to #380.  Commits and comments
> written before the rename say #377; they mean this file.

## Status

Completed 2026-09-23.

Every implementation step is either built or was deliberately replaced
by #382 (the mailbox is the installation); the steps below say which,
and what replaced each.  Both open questions are answered.  Nothing is
deferred.

How it was verified, on 2026-09-23:

- `scripts/test-mailbox-selection.sh` was run and every case passed —
  argument handling, mailbox resolution, recipient ambiguity,
  unresolvable recipients surviving the cleanup sweep, and a port that
  will not bind.
- The machine-side step is done.  `/home/ritz/notes/rmail/config` says
  `name = kuvalu-notes` and `port = 8026`.  Every "rmail starting" line
  in `/tmp/kuvalu-notes.log` since 2026-09-22 13:09 reads
  `name=kuvalu-notes port=8026`, the latest at 2026-09-23 08:47:35,
  while `/tmp/kuvalu-mail.log` starts as `name=kuvalu port=8025`.  The
  two mailboxes no longer share an identity.
- `ps -eo pid,lstart,args | grep rmail` shows exactly two daemons, one
  per mailbox, each started with its mailbox's own config file as its
  only argument.  `/var/service` links `kuvalu-mail` and
  `kuvalu-notes` and nothing else of rmail's.
- The two gaps found while checking this for closure — both about a
  service name picked with `--service-name` not starting with `rmail` —
  were fixed (commit aad3f4c) and checked: the log viewer with no
  argument lists `kuvalu-mail` and `kuvalu-notes` and follows the one
  chosen, `view-logs.sh kuvalu-notes` follows directly, and
  `git check-ignore` reports `kuvalu-notes-run`,
  `kuvalu-notes.service`, `rmail-home-ritz-mail.nix` and `x-init` as
  ignored.

## Summary

The installer supports one mailbox per config file — that was the point
of #343 and #344, which made config filenames carry a slug derived from
the mailbox path so `~/mail` and `~/notes/rmail` get distinct files.
Service generation never got the same treatment.  Every install writes a
service named `rmail`, to a fixed path, logging to a fixed file.

Installing a second mailbox therefore does not add a second service.  It
silently replaces the first one.  The first mailbox stops being served
with no error at either install time or run time.

(That was the state when this issue was written.  #382 later moved
each config inside its own mailbox, which removed the config-filename
slug; the service name is now the one place the slug is still used.)

## Current Behavior

### The installer (`scripts/install.sh`)

**Installing a second mailbox adds a second service.**  The service
name derives from the mailbox path — leading slash stripped, remaining
slashes turned into dashes, prefixed `rmail-` — so `/home/ritz/mail` is
served by `rmail-home-ritz-mail`.  The name is offered at a prompt with
that as the default, and can be overridden with `--service-name`.  It
is validated like the identity name: letters, numbers, hyphens,
underscores.  It is threaded through all five init-system branches —
the generated file in the project root, the installed unit path, the
log path, the OpenRC pidfile, the NixOS attribute name, and the printed
instructions, which were the actual delivery mechanism for the bug.

**Each service logs to its own file**, `/tmp/<service>.log`.

**The printed instructions copy rather than move**, so the generated
file stays in the project root as a record of what was installed.

**Before anything is written, the installer scans for existing
services.**  A service named exactly `rmail` — the layout from before
this change — is looked for in all five init systems' locations and
reported, with a description of how to move it onto the new naming,
but never renamed.

**At service-generation time a clash is refused.**  If a service by the
chosen name already exists in any init system's location and its file
does not name this mailbox's config, the install stops with an error
naming the file found and suggesting `--service-name`.  If it does name
this mailbox's config, the install reports an update.  There is
deliberately no automatic fallback to another name.  This check runs at
generation time because that is the last moment the script still
controls what happens — it never escalates privileges.

**What the installer no longer does, because #382 replaced it:** it
does not read other mailboxes' configs.  The port is checked against
what the system says is listening (`ss`, else `netstat`), which warns
and offers another random port rather than refusing, because a mailbox
that is installed but stopped holds no port and cannot be seen.  The
identity name is not checked against other mailboxes at all; the
daemon's ambiguous-recipient refusal (below) guards the real condition
instead.  There is no project-root `config` symlink to manage, because
the config is a real file inside its mailbox.

### Supporting files

- `.gitignore` ignores the generated service files as `/*.nix`,
  `/*.service`, `/*-run`, `/*-init` — anchored to the project root and
  not tied to an `rmail` prefix, because `--service-name` allows any
  name.  No tracked file at the root has any of those shapes.
- `scripts/view-logs.sh` finds logs by content rather than by name: a
  `/tmp/*.log` counts as an rmail log when its first line contains
  ` rmail starting: name=`, and the legacy `/tmp/rmail.log` is accepted
  by name since it may predate that line.  With one log it is followed
  directly; with several they are listed newest first and one is
  chosen; an argument may be a path or a service name.  The `.logs`
  symlink is gone: it named one log, and there is no longer one log.
- The service documentation (`docs/.templates/service.md`, generated
  into `docs/service.md`) says there is no `--config` flag and shows
  the positional config-file form.

### The daemon (`rmail.lua`)

**The daemon takes a config file and nothing else.**  Both
config-resolution fallbacks are gone, including the one that rebuilt
the installer's path-to-slug transform in a second place.  A directory
argument stops with an error naming the config form, which is what a
service file written before this change does on its next restart.

**The mailbox served is the directory the config file sits in.**  (This
file first recorded a relative `mail = ...` line resolving against the
config's directory; #382 then removed the `mail` key entirely.  A
leftover `mail =` line is ignored.)  The portable drive's launcher
hands the daemon `<mailbox>/config`, so the pair still needs nothing
but its own location to work from whatever mount point a host picks.

**A recipient naming both the configured identity and a real contact
is refused.**  In the outbox sync, the daemon logs both readings and
writes an `// AMBIGUOUS RECIPIENT` note into the outbox file beside the
`to:` line, and the message stays put until one of the two names is
changed.

**An outbox file with an unresolvable recipient is kept.**  The
cleanup pass at the end of an outbox sync distinguishes three ways a
recipient list can be empty: everyone was delivered to (delete), work
is queued this cycle (leave it for the retry), or nobody in the `to:`
line could be resolved (leave it, with the marker in it).  The unknown
contact and ambiguous recipient sites share one insertion routine,
which also puts the marker on its own line when the `to:` line is the
last line of the file.

### On this machine

`/etc/sv` holds five relevant service directories:

| created | name | serves | enabled |
|---|---|---|---|
| Aug 25 10:27 | `rmail` | `notes/rmail` | no |
| Aug 26 10:55 | `rmail-home-ritz-mail` | `~/mail` | no |
| Aug 26 10:55 | `rmail-home-ritz-notes-rmail` | `notes/rmail` | no |
| Aug 26 11:10 | `kuvalu-mail` | `~/mail` | **yes, running** |
| Aug 26 11:10 | `kuvalu-notes` | `notes/rmail` | **yes, running** |

The two enabled services each pass their mailbox's config file.  The
mailbox at `/home/ritz/mail` answers as `kuvalu` on 8025; the mailbox
at `/home/ritz/notes/rmail` answers as `kuvalu-notes` on 8026.  The
three unenabled directories are leftovers and are left alone: removing
a service directory is the operator's call, which is the same principle
as the migration note below.

## Intended Behavior

Installing a second mailbox adds a second service alongside the first.
Both daemons run.  Neither install touches the other's files.  A third
install behaves the same way.

The service name derives from the same mailbox-path slug the installer
already computes for the config filename, so uniqueness is inherited
from the filesystem rather than from the user remembering to pick a
different name.  A mailbox at `/home/ritz/mail` yields a service named
`rmail-home-ritz-mail`.  The name is offered as a default at a prompt so
a shorter one can be typed.

Each service writes to its own log file, named from the same slug.

Before writing anything, the installer reports what rmail installations
already exist on the machine, and refuses to overwrite a service
belonging to a different mailbox.

## Suggested Implementation Steps

Ordered so each step leaves the installer working.  Each step says what
was built, or which #382 change replaced it.

1. **Derive a service name.**  The mailbox-path slug already exists in
   the installer as the value behind the config filename.  Reuse it to
   build the service name, and add a prompt with that as the default,
   alongside the existing prompts for mailbox directory, identity name,
   and port.  Validate it the same way the identity name is validated —
   letters, numbers, hyphens, underscores.
   *Built:* `SERVICE_SLUG`, `DEFAULT_SERVICE` and the `service_name`
   prompt in `scripts/install.sh`, with `--service-name` as the
   override.  The config filename no longer uses the slug (#382), so
   the service name is now its only user.

2. **Thread the service name through all five init-system branches.**
   Every hardcoded `rmail` in a path or unit name becomes the derived
   name.  The NixOS branch needs it in the attribute name as well as
   the filename.  The printed instructions must use it too — those
   instructions were the actual delivery mechanism for this bug.
   *Built:* `RMAIL_SERVICE` in the NixOS, systemd user, systemd system,
   runit and OpenRC branches of `scripts/install.sh`, including
   `systemd.services."$RMAIL_SERVICE"` and the OpenRC pidfile.

3. **Derive a per-service log path** from the same slug and use it in
   all five branches.
   *Built:* `RMAIL_SERVICE_LOG="/tmp/$RMAIL_SERVICE.log"`.

4. **Name the generated file in the project root after the service.**
   Otherwise a second install clobbers the first's generated file before
   the user has installed it.
   *Built:* `<service>.nix`, `<service>.service`, `<service>-run`,
   `<service>-init` in the project root.

5. **Convert the `.gitignore` service entries to glob patterns** so
   slug-suffixed generated files stay ignored.
   *Built:* first as `rmail*` globs, then (commit aad3f4c) as
   root-anchored `/*.nix`, `/*.service`, `/*-run`, `/*-init`, because a
   name chosen with `--service-name` need not start with `rmail`.

6. **Stop repointing the project-root config symlink unconditionally.**
   Either leave it once it exists, or make it explicit which mailbox is
   primary and say so in the summary output.
   *Built, then made moot by #382:* the first install claimed the
   symlink and later ones reported what they found.  Once the config
   moved inside the mailbox, there is no symlink to manage; a
   project-root `config` is only a gitignored local testing file.

7. **Add an existing-install scan** that runs before any file is
   written.  It reads the rmail config directory for sibling configs and
   checks the init system's service location for names starting with the
   rmail prefix, then reports what it found.  If the target service name
   already exists and points at a different config, stop with an error
   rather than proceeding — a fallback that silently picks another name
   would reintroduce the class of surprise this issue is about.
   *Partly built, partly replaced by #382.*  Built and still in place:
   `scan_existing_installs` looks for a pre-slug `rmail` service in all
   five init systems' locations and reports it; `service_exists`
   finds a unit by name, and the service-setup block refuses a clash
   that does not name this mailbox's config, with no fallback name.
   Replaced: reading sibling configs.  #382 moved each config into its
   own mailbox, so no shared directory of configs exists to read, and
   one mailbox reading another's files was judged the wrong
   relationship.

8. **Check the chosen port against every other rmail config** found in
   step 7, and re-prompt on collision.
   *Replaced by #382:* `port_holder` asks the system what is listening
   on the port (`ss -ltnH`, else `netstat -ltn`) and warns and offers
   another random port on a hit (`--silent` exits instead).  It sees
   more — any program, not just rmail — and less — a stopped mailbox
   holds nothing — which is why it warns rather than refuses.  The
   daemon is where a collision becomes certain: it claims its port
   before probing the router, and when it cannot bind it stops with a
   plain explanation and leaves a note in its own inbox.

9. **Teach the log viewer to handle several logs** — list what exists,
   let one be chosen, and keep the single-log fast path when only one is
   present.  The hidden `.logs` symlink in the project root needs the
   same treatment or needs to be dropped in favour of the viewer.
   *Built:* `list_logs`, `service_of` and `follow` in
   `scripts/view-logs.sh`, with `.logs` dropped.  Commit aad3f4c added
   `is_rmail_log`, which recognises a log by its first line rather
   than by an `rmail` filename prefix.

10. **Fix the `--config` flag in the multiple-instances documentation**
    to the positional form the daemon actually accepts, and replace the
    hand-copied service-file instructions with a pointer at re-running
    the installer, once the installer is the thing that does this
    correctly.
    *Built:* in `docs/.templates/service.md`, from which
    `docs/service.md` is generated.

11. **Reject the mailbox-directory argument** with a usage error naming
    the config-file form, and remove both config-resolution fallbacks.
    *Built:* the argument block at the top of `rmail.lua` (`usage`,
    `is_dir`, `parse_config_file`); the mailbox is the config's own
    directory.

12. **Update the USB-drive launcher** to pass the mailbox's config path
    rather than the mailbox directory.
    *Built, and its first form replaced by #382.*  The launcher written
    by `scripts/make-mailbox-drive.sh` runs `run-rmail.sh
    "$MAILBOX_DIR/config"`.  This file first did that with a relative
    `mail = .` line in the drive's config; #382 removed the `mail` key,
    so the config's location alone decides the mailbox.

13. **Reject an identity name already claimed by another mailbox** on
    the machine and re-prompt, using the sibling configs gathered by the
    existing-install scan.
    *Built, then replaced by #382.*  The danger was never two configs
    holding the same string; it was a `to:` line that resolves both as
    this mailbox's identity and as a contact, which one mailbox can
    walk into with no sibling anywhere by adding a contact named after
    itself.  Step 14 checks that real condition at the moment it
    arises, so the install-time check was removed along with the
    sibling-config reading.  The reasoning is recorded beside the name
    prompt in `scripts/install.sh`.

14. **Make the daemon refuse an ambiguous recipient** rather than
    resolving it silently.  A `to:` line that matches the configured
    identity name *and* names a real contact currently self-delivers
    with the contact losing quietly; that should be an error naming both
    interpretations.
    *Built:* in `sync_outbox` in `rmail.lua`, before the self-delivery
    test; it logs, marks the file `AMBIGUOUS RECIPIENT`, and holds the
    message.

15. **Hold outbox files with an unresolvable recipient back from the
    cleanup sweep**, the way files with queued work are already held
    back.  Both marker sites — unknown contact and ambiguous recipient
    — mark the file as held.  The two sites should share one marker
    routine rather than one copying the other.
    *Built:* `mark_recipient_problem` in `rmail.lua` is the shared
    marker routine; `outbox_files_with_unresolved_recipients` in
    `sync_outbox` holds those files back from the cleanup sweep.

**Test:** `scripts/test-mailbox-selection.sh` (see Verification).

## Migration

Machines installed before this change have a service literally named
`rmail`.  The existing-install scan in step 7 should recognise that name
as the pre-slug layout, report which config it points at, and describe
the rename rather than performing it — moving a supervised service
directory stops the daemon, and that should be a decision the operator
makes deliberately rather than a side effect of running an installer.

Built as described: `scan_existing_installs` sets `PRE_SLUG_SERVICE`
and the installer prints a warning, touching nothing.

## Decisions

**The installer never escalates privileges.**  It generates service
files and prints instructions; the operator installs them.  This is a
standing constraint, not a default to revisit — so the printed
instructions are the permanent delivery mechanism and have to be
collision-proof on their own.  Two consequences fold into the steps
above: the instructions must carry the derived service name, and the
existing-install check must run at *generate* time, because that is the
last moment the script still controls what happens.

The instructions should also use a copy rather than a move, so the
generated file stays in the project root as a record of what was
installed instead of disappearing into the system service directory.

**The daemon takes only the config-file form of its argument.**  The
mailbox-directory form is dropped.  The argument itself stays — it is
what selects which mailbox a daemon serves, and removing it would mean
one hardcoded mailbox per machine, which is the capability this issue
exists to protect.

The directory form resolves a config through two stacked fallbacks, and
they are not equally defensible:

- **A file named `config` inside the mailbox directory.**  A fixed
  relative path.  Benign.
- **Otherwise a derived path** built by stripping the mailbox path's
  leading slash, turning every remaining slash into a dash, and looking
  under the rmail config directory in the user's home.

The second is the real defect.  It reimplements the installer's
path-to-slug transform in a second location, so the two must agree
forever or the daemon silently opens a config the operator never named.
It also depends on the home directory being set to whatever the service
file exported — which is why every generated run script carries an
explicit home-directory export propping it up.  Killing that guess is
the correctness fix, and it is what makes the config unambiguously the
source of truth.

The directory form's only live consumer is the USB-drive launcher
generated by the mailbox-drive script.  That launcher knows its mailbox
by construction — its own location plus a mailbox name baked in at
generation time — and the config sits at a fixed relative path inside.
Passing the config path instead relocates that convention from the
daemon into the launcher rather than eliminating it; the argument for
doing so is one entry point instead of two, not correctness.

Service files generated before this change will fail with a usage error
on their next restart, which is a better outcome than the current silent
wrong-mailbox behaviour.

Two additional implementation steps follow from this: steps 11 and 12
above.

**Identity names must be unique across mailboxes on one machine.**
Enforced at install time as an error, not a warning.  *(Later
reversed by #382 — see step 13.  The reasoning below still explains
why step 14 exists.)*

The daemon decides self-delivery by comparing each `to:` line against
its own configured identity name, and that comparison runs *before* any
contacts lookup.  A recipient name matching your own identity is
delivered straight into your own inbox regardless of whether a contact
by that name exists and regardless of what address or token that contact
carries.

So two mailboxes sharing an identity name is not a cosmetic duplication.
Addressing mail from one to the other by that shared name makes the
sending daemon write the message into its own inbox, log it as
self-delivered, and mark the recipient satisfied in its tracking state.
Nothing reaches the other mailbox.  There is no error, no retry, and no
warning.  The tracking entry is additionally stamped as a self-message,
so a later rename still leaves the cleanup path treating it as one.

The skip-myself filter compounds this: contact iteration for IP-change
and IPv6-change notifications and for the NAT-insecurity warning all
guard with "unless this contact is me", so a contact entry named after
the shared identity is skipped by every one of them.

The existing-install scan in step 7 already reads sibling configs for
the port check, so the identity names are available at no extra cost.

Two further implementation steps followed: steps 13 and 14 above.

**Refusing a recipient must not destroy the message.**  Found while
building step 14, and it has to be in place before step 14 can be, or
the refusal is worse than what it replaces.

The end of an outbox sync sweeps away any outbox file whose recipient
list is empty.  That is right when the list emptied because every
recipient was delivered to and struck off — the message is finished
with, and leaving it would resend it.  But a file whose `to:` line
resolved to nobody never had an entry in that list to begin with, and
is indistinguishable at the sweep.  It was deleted in the same sync
cycle that wrote the explanatory marker into it.

This already applied to an unknown contact, so a message addressed to
a name not in the contacts file was silently destroyed seconds after
being written.  The ambiguity refusal would have behaved the same way.
That became step 15.

## Answered questions

**The two `kuvalu` mailboxes.**  `kuvalu` is the name of this computer,
and it stays with the mailbox at `/home/ritz/mail` on port 8025.  The
mailbox at `/home/ritz/notes/rmail` on port 8026 becomes `kuvalu-notes`.

The migration turned out to cost nothing, which the question had
assumed it would not.  Neither mailbox has a contact named `kuvalu`,
neither lists the other as a contact at all, and the notes mailbox has
an empty contacts file and empty inbox and outbox state.  So no
existing message's resolution changes, and the shared name had never
had an opportunity to swallow anything.  The rename is one line in
`~/.config/rmail/config-home-ritz-notes-rmail`, and takes effect when
that mailbox's service is restarted.  (That config has since moved to
`/home/ritz/notes/rmail/config` under #382; the service was restarted
and has answered as `kuvalu-notes` since 2026-09-22 13:09.)

The name a contact sees is unaffected either way: contacts address you
by whatever name they wrote in their own contacts file, and the
identity field is only ever compared locally.

**The health check keeps answering with the real name.**  Two mailboxes
on one machine differ by port, and the name in the reply is what tells
you which of them answered on a given port — the diagnostic this issue's
whole subject matter makes worth having.  The name is not a secret and
the config comment now says so.

Worth recording against a future reading of that endpoint: it does not
exercise decryption.  The daemon reads the first four bytes of a
connection and takes `GET ` as a health check, replying before any key
is involved.  It proves the port is open and a daemon is alive, and
nothing about whether a contact's token works.

## Separate concern found while investigating

The generated config's comment above the identity name says it is
"never transmitted" and that each contact sees whatever name they
assigned in their own contacts file.  That is not accurate.  The daemon
treats any connection beginning with the four bytes `GET ` as a
plaintext health check and replies with a JSON object containing the
identity name — no decryption, no authentication.  The README documents
exactly this call as the way to confirm a working install, so anyone who
reaches the port learns the name.

The LAN discovery broadcast also carries the name, but encrypts it with
the destination contact's shared token first, so that path matches the
documented claim.

The comment is fixed, in both the installer's config template and the
portable drive's.  Both now say the name is not carried in the mail you
send but is not a secret either, and name the health check as the way
it gets out.  What the health check should answer with is settled in
the answered questions above.

## History: how the operator had already worked around this

Recorded because it is the evidence behind two of the decisions.

The first `/etc/sv` directory in the table above is what the installer
produced: one service, named `rmail`, serving whichever mailbox was
installed last.  The next two were then built by hand on the following
morning, using exactly the slug naming this issue proposes — including
the per-service log paths.  Half an hour after that they were
superseded by a second hand-built pair under shorter names, and those
are the two actually supervised and running.

So both mailboxes are served, and neither is served by anything the
installer made.  The operator had already worked around this by hand
before the issue was written, which is why the symptom never showed up
as a mailbox going quiet.

Two things follow.  The derived name is the right default, since it is
what somebody reached for unprompted when solving this themselves.  And
the prompt that allows a shorter one is not a nicety — the same person
replaced those derived names with `kuvalu-mail` and `kuvalu-notes`
within the hour, which is the whole argument for `--service-name`.

When this was first checked, re-running the fixed installer for either
mailbox found its slug-named directory already present and pointing at
the same config, so it reported an update rather than refusing.  Since
#382 moved the configs, those two unenabled directories still name the
old `~/.config/rmail/config-home-ritz-*` files, so a re-run with the
default name now refuses, saying the existing service does not serve
this mailbox.  That is the no-fallback rule doing its job on a stale
unit: the operator removes the leftover directory or picks another name
with `--service-name`.

That same `--service-name` case is what the last two gaps were about:
the log viewer and `.gitignore` both still assumed an `rmail` prefix,
so on this machine — whose only services are `kuvalu-*` — the viewer
found no logs at all.  Both now work for any name (steps 5 and 9).

## Verification

`scripts/test-mailbox-selection.sh` covers what this issue changed in
the daemon, alongside the port rules added by #382.  It builds
throwaway mailboxes in RAM and starts the real daemon against each,
checking that: an empty argument and a mailbox directory are each
refused; a config planted at the old slug path is not found from a
directory argument; the mailbox served is the directory the config
sits in, and a leftover `mail =` line pointing elsewhere is ignored; an
ambiguous recipient is logged, marked in the outbox file, not
self-delivered, and not deleted; plain self-delivery still works when
the name is not also a contact; and a message to an unknown contact
survives the cleanup sweep with its marker, including when the `to:`
line has no newline after it.  Run it for the current case list and
results.

It needs a working network — the daemon looks its own public IP up
over DNS during startup, before it reaches its first outbox sync.

The installer-side and machine-side checks are listed under Status.

## Related

- #343 — introduced the per-mailbox config file.  This issue is the
  unfinished half of that change: config filenames were made unique,
  service names were not.
- #344 — documents the slug as intentional, not path mangling.  The same
  slug is the fix here.
- #205 — moved service logs to RAM-backed `/tmp`, and is where the
  single hardcoded log path originates.
- #382 — the mailbox is the installation.  Moved each config inside its
  mailbox, removed the `mail` key, and replaced this issue's
  sibling-config port and identity checks (steps 7, 8, 12, 13).
