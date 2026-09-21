# #377 — Install script: every mailbox generates the same service name

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

**What is still true.**  The daemon continues to accept a mailbox
directory as its argument and continues to resolve a config from it
through two stacked fallbacks, the second of which reimplements the
installer's path-to-slug transform in a second place.  Steps 11 and 12
below are unstarted.  Step 14 is unstarted: a recipient matching both
the configured identity and a real contact still self-delivers silently.

**Verified on this machine.**  The two mailboxes at `/home/ritz/mail`
and `/home/ritz/notes/rmail` share the identity `kuvalu`, and the single
installed service at `/etc/sv/rmail/run` serves the second one — so the
first mailbox has no service at all, which is this bug's signature.  The
new scan detects and reports both of these.  Neither has been changed;
see the open questions.

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
11. Reject the mailbox-directory argument — **not started**.
12. Update the USB-drive launcher — **not started**.
13. Reject a duplicate identity name — done.
14. Daemon refuses an ambiguous recipient — **not started**.

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

## Open questions

- This machine currently has two mailboxes both named `kuvalu`, created
  before the uniqueness rule above existed.  Renaming one changes how
  its existing contacts' messages resolve, so the migration is not just
  editing a config field — it needs working through before either
  mailbox is renamed.
- The plaintext health-check response hands the identity name to any
  unauthenticated caller (see the separate concern below).  Should that
  endpoint answer with the real name, a fixed placeholder, or nothing at
  all?  It is documented in the README as the way to verify an install,
  so changing it changes that procedure too.

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

Fixing the comment is a small change to the config template written to
every install.  Deciding what the health check should answer with is
the open question above.

## Status

Open.  The installer no longer produces one mailbox per machine, which
was the reported symptom.  Steps 11, 12 and 14 remain, and both open
questions above are unanswered — the second of which has to be decided
before the two `kuvalu` mailboxes on this machine can be reconciled.
