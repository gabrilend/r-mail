# #381 — Install script: every mailbox generates the same service name

> Filed as #377 and renumbered to #381.  Another machine had already
> published its own #377 (per-contact sync timers) before this one was
> pushed, so this is the copy that moved — the same way the
> capability-URL issue moved from #376 to #380.  Commits and comments
> written before the rename say #377; they mean this file.

## Summary

The installer supports one mailbox per config file — that was the point
of #343 and #344, which made config filenames carry a slug derived from
the mailbox path so `~/mail` and `~/notes/rmail` get distinct files.
Service generation never got the same treatment.  Every install writes a
service named `rmail`, to a fixed path, logging to a fixed file.

Installing a second mailbox therefore does not add a second service.  It
silently replaces the first one.  The first mailbox stops being served
with no error at either install time or run time.

## Current behavior

The installer half of this is done.  The daemon half is not.

**Installing a second mailbox now adds a second service.**  The service
name derives from the same mailbox-path slug that already named the
config file, so `/home/ritz/mail` is served by `rmail-home-ritz-mail`.
The name is offered at a prompt with that as the default, and can be
overridden with `--service-name`.  It is threaded through all five
init-system branches — the generated file in the project root, the
installed unit path, the log path, the OpenRC pidfile, the NixOS
attribute name, and the printed instructions, which were the actual
delivery mechanism for the bug.

Three checks run before anything is written.  Sibling configs are read
and reported.  An identity name already claimed by another mailbox is
refused.  A port already claimed is refused.  At service-generation
time — the last moment the script still controls what happens, since it
never escalates privileges — a service name that exists and points at a
different config stops the install rather than overwriting it.  There is
deliberately no automatic fallback to another name.

The printed instructions now copy rather than move, so the generated
file stays in the project root as a record of what was installed.

The project-root `config` symlink is claimed by the first install and
left alone by later ones, which report what they found instead.

`.gitignore` matches the generated files by glob.  The log viewer lists
several logs and offers a choice, keeping the single-log fast path when
only one exists.  The `.logs` symlink is gone: it named one log, and
there is no longer one log.

**The daemon half is done too.**  The daemon takes a config file and
nothing else.  Both config-resolution fallbacks are gone, including the
one that rebuilt the installer's path-to-slug transform in a second
place.  A directory argument stops with an error naming the config
form, which is what a service file written before this change now does
on its next restart.

A `mail = ...` line that is relative resolves against the directory
holding the config file rather than the working directory.  That is
what replaces the directory form for the portable drive: its config
sits inside its mailbox and says `mail = .`, so the pair still needs
nothing but its own location to work from whatever mount point a host
picks, and the launcher hands the daemon the config path.

A recipient naming both the configured identity and a real contact is
refused.  The daemon logs both readings and writes an `// AMBIGUOUS
RECIPIENT` note into the outbox file beside the `to:` line, and the
message stays put until one of the two names is changed.

**A message-destroying bug turned up underneath step 14, and is
fixed.**  The cleanup pass at the end of an outbox sync deletes any
outbox file whose recipient list has emptied, on the reasoning that
every recipient was delivered to and struck off.  A file whose `to:`
line named nobody resolvable arrives at that pass looking identical,
and was deleted — body and all — in the same cycle that wrote the
marker explaining the problem into it.

This was not introduced by the ambiguity refusal; it was already the
behaviour for an unknown contact, and had been for as long as the
marker has existed.  Addressing a message to a name not in your
contacts file wrote you a helpful note and then deleted the message
you had written, within seconds, with no way back.  The refusal in
step 14 would have inherited it exactly.

The cleanup pass now distinguishes three ways a recipient list can be
empty: everyone was delivered to (delete), work is queued this cycle
(leave it for the retry), or nobody in the `to:` line could be
resolved (leave it, with the marker in it).  The two marker sites
share one insertion routine, which also fixes a `to:` line on the last
line of a file getting the marker glued onto its end.

**Verified on this machine, and the workaround found there is worth
recording.**  `/etc/sv` holds five relevant service directories:

| created | name | serves | enabled |
|---|---|---|---|
| Aug 25 10:27 | `rmail` | `notes/rmail` | no |
| Aug 26 10:55 | `rmail-home-ritz-mail` | `~/mail` | no |
| Aug 26 10:55 | `rmail-home-ritz-notes-rmail` | `notes/rmail` | no |
| Aug 26 11:10 | `kuvalu-mail` | `~/mail` | **yes, running** |
| Aug 26 11:10 | `kuvalu-notes` | `notes/rmail` | **yes, running** |

The first is what the installer produced: one service, named `rmail`,
serving whichever mailbox was installed last.  The next two were then
built by hand on the following morning, using exactly the slug naming
this issue proposes — including the per-service log paths.  Half an hour
after that they were superseded by a second hand-built pair under
shorter names, and those are the two actually supervised and running.

So both mailboxes are served, and neither is served by anything the
installer made.  The operator had already worked around this by hand
before the issue was written, which is why the symptom never showed up
as a mailbox going quiet.

Two things follow.  The derived name is the right default, since it is
what somebody reached for unprompted when solving this themselves.  And
the prompt that allows a shorter one is not a nicety — the same person
replaced those derived names with `kuvalu-mail` and `kuvalu-notes`
within the hour, which is the whole argument for `--service-name`.

Re-running the fixed installer for either mailbox now finds its
slug-named directory already present and pointing at the same config,
so it reports an update rather than refusing.  The three unenabled
directories are leftovers and are left alone: removing a service
directory is the operator's call, which is the same principle as the
migration note below.

The two mailboxes also share the identity `kuvalu`.  The new scan
detects and reports that.  Nothing has been changed; see the open
questions.

### Steps done

1. Derive a service name — done.
2. Thread it through all five branches — done.
3. Per-service log path — done.
4. Name the generated file after the service — done.
5. `.gitignore` globs — done.
6. Stop repointing the project-root config symlink — done.
7. Existing-install scan — done, including pre-slug detection.
8. Port collision check — done.
9. Log viewer handles several logs — done; `.logs` dropped.
10. Fix the `--config` flag in the docs — done, in the template.
11. Reject the mailbox-directory argument — done.
12. Update the USB-drive launcher — done, via a relative `mail`.
13. Reject a duplicate identity name — done.
14. Daemon refuses an ambiguous recipient — done.
15. Keep an unresolvable recipient's message — done.

Every step has an implementation.  What is not done is the two open
questions at the bottom, and the two `kuvalu` mailboxes on this machine
that the second of them blocks.

## Intended behavior

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

## Suggested implementation steps

Ordered so each step leaves the installer working.

1. **Derive a service name.**  The mailbox-path slug already exists in
   the installer as the value behind the config filename.  Reuse it to
   build the service name, and add a prompt with that as the default,
   alongside the existing prompts for mailbox directory, identity name,
   and port.  Validate it the same way the identity name is validated —
   letters, numbers, hyphens, underscores.

2. **Thread the service name through all five init-system branches.**
   Every hardcoded `rmail` in a path or unit name becomes the derived
   name.  The NixOS branch needs it in the attribute name as well as
   the filename.  The printed instructions must use it too — those
   instructions were the actual delivery mechanism for this bug.

3. **Derive a per-service log path** from the same slug and use it in
   all five branches.

4. **Name the generated file in the project root after the service.**
   Otherwise a second install clobbers the first's generated file before
   the user has installed it.

5. **Convert the `.gitignore` service entries to glob patterns** so
   slug-suffixed generated files stay ignored.

6. **Stop repointing the project-root config symlink unconditionally.**
   Either leave it once it exists, or make it explicit which mailbox is
   primary and say so in the summary output.

7. **Add an existing-install scan** that runs before any file is
   written.  It reads the rmail config directory for sibling configs and
   checks the init system's service location for names starting with the
   rmail prefix, then reports what it found.  If the target service name
   already exists and points at a different config, stop with an error
   rather than proceeding — a fallback that silently picks another name
   would reintroduce the class of surprise this issue is about.

8. **Check the chosen port against every other rmail config** found in
   step 7, and re-prompt on collision.

9. **Teach the log viewer to handle several logs** — list what exists,
   let one be chosen, and keep the single-log fast path when only one is
   present.  The hidden `.logs` symlink in the project root needs the
   same treatment or needs to be dropped in favour of the viewer.

10. **Fix the `--config` flag in the multiple-instances documentation**
    to the positional form the daemon actually accepts, and replace the
    hand-copied service-file instructions with a pointer at re-running
    the installer, once the installer is the thing that does this
    correctly.

## Migration

Machines installed before this change have a service literally named
`rmail`.  The existing-install scan in step 7 should recognise that name
as the pre-slug layout, report which config it points at, and describe
the rename rather than performing it — moving a supervised service
directory stops the daemon, and that should be a decision the operator
makes deliberately rather than a side effect of running an installer.

## Related

- #343 — introduced the per-mailbox config file.  This issue is the
  unfinished half of that change: config filenames were made unique,
  service names were not.
- #344 — documents the slug as intentional, not path mangling.  The same
  slug is the fix here.
- #205 — moved service logs to RAM-backed `/tmp`, and is where the
  single hardcoded log path originates.

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

Two additional implementation steps follow from this:

11. **Reject the mailbox-directory argument** with a usage error naming
    the config-file form, and remove both config-resolution fallbacks.
12. **Update the USB-drive launcher** to pass the mailbox's config path
    rather than the mailbox directory.

**Identity names must be unique across mailboxes on one machine.**
Enforced at install time as an error, not a warning.

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

Two further implementation steps:

13. **Reject an identity name already claimed by another mailbox** on
    the machine and re-prompt, using the sibling configs gathered by the
    existing-install scan.
14. **Make the daemon refuse an ambiguous recipient** rather than
    resolving it silently.  A `to:` line that matches the configured
    identity name *and* names a real contact currently self-delivers
    with the contact losing quietly; that should be an error naming both
    interpretations.

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

15. **Hold outbox files with an unresolvable recipient back from the
    cleanup sweep**, the way files with queued work are already held
    back.  Both marker sites — unknown contact and ambiguous recipient
    — mark the file as held.  The two sites should share one marker
    routine rather than one copying the other.

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
that mailbox's service is restarted.

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
it gets out.  Deciding what the health check should answer with is the
open question above, and is untouched.

## Verification

`scripts/test-mailbox-selection.sh` covers what this issue changed in
the daemon.  It builds throwaway mailboxes in RAM and starts the real
daemon against each, checking that: an empty argument, a mailbox
directory, and a config with no `mail` line are each refused; a config
planted at the old slug path is not found from a directory argument;
an absolute `mail` is served as written and a relative one resolves
against the config's directory; an ambiguous recipient is logged,
marked in the outbox file, not self-delivered, and not deleted; plain
self-delivery still works when the name is not also a contact; and a
message to an unknown contact survives the cleanup sweep with its
marker.

It needs a working network — the daemon looks its own public IP up
over DNS during startup, before it reaches its first outbox sync.

## Status

In progress.  Every implementation step has been carried out, the
daemon's half is verified by the test above, and both open questions
are answered.

What remains is on the machine rather than in the code: the notes
mailbox's config now says `kuvalu-notes`, and its service has to be
restarted before the running daemon knows that.  Until then the two
daemons are still both answering to `kuvalu`.
