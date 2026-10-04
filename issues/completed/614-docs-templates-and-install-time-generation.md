# Treat docs/ as build artifacts generated from docs/.templates/

## Current Behavior

Complete, with both extensions of 2026-10-04 (the second: the guide's
examples are the templates, filled by `scripts/fill-guide-examples.lua`,
and checked by `scripts/test-service-templates.sh`).

Built, including the first extension of 2026-10-04 (owner: "yes please" to
moving the service files into templates and trimming the service guide
to this machine's service manager).

- The documents are built from `docs/.templates/` as described in the
  rest of this file, and the built `service.md` keeps only the section
  for this machine's service manager (all four when none is found, with
  a line saying so).  The templates keep every section.
- The six service files the installer can write are templates in
  `scripts/.templates/services/`, filled by `fill_service_template`.
  Filled with the same values, they are byte for byte what the inline
  blocks they replaced wrote (checked 2026-10-04 for all six, with paths
  holding `&` and `|`).
- `scripts/detect-service-manager.sh` is the one place that decides the
  service manager; the installer and `generate-docs.sh` both ask it.
- `scripts/test-service-templates.sh` checks all of it.

Before the extension, every build kept every section, and the service
files' text lived inside `scripts/install.sh` as blocks filled in by the
shell.  The restart script (#622) was the first thing built the
template way, one folded block per service manager.

## Intended Behavior (2026-10-04 extension)

- **Service files come from templates**: `scripts/.templates/services/`,
  one file per kind the installer writes — systemd user service, systemd
  system service, runit `run` script, OpenRC init script, and NixOS
  module (one using the system's Lua, one using a Lua given by path).
  Each holds `@NAME@` placeholders for the values the installer knows
  (mailbox, program folder, config file, Lua, log file, service name,
  user, home folder, port).  The installer fills one in and refuses if
  any placeholder is left unfilled.  The files written are byte for byte
  what the inline blocks wrote.
- **The documents keep only this machine's service manager**:
  `service.md` marks each manager's section with
  `<!-- {{{ manager: X -->` … `<!-- }}} manager: X -->`, and the docs
  build keeps the section for this machine's manager and drops the
  others.  The templates still hold every section, so the versions in
  the repository stay complete.  With no manager found, every section is
  kept and the build says so.
- **One place decides the service manager**: a small script prints it
  (`nixos`, `systemd`, `runit`, `openrc` or `unknown`), used by the
  installer and by `generate-docs.sh`, so the two can never disagree.

## Overview

Several docs reference paths that depend on the user's install location —
most notably the Lua interpreter path in the scripting tutorial. Today
these paths are hardcoded placeholders that every user has to mentally
substitute. The install script knows the real paths, so it should fill
them in.

Treat `docs/` as a build artifact, generated from `docs/.templates/` at
install time. Developers edit the templates; the generated docs are
gitignored.

## Chosen approach

After exploring several options (see "Options considered" below), the
chosen approach is:

- `docs/.templates/` holds the source-of-truth `.md` files with
  human-readable placeholder paths (e.g. `/home/you/programs/email/...`).
  GitHub viewers reading templates directly see sensible example paths,
  not `{{VAR}}` tokens.
- `docs/` is otherwise empty in git, containing only a single
  `looking-for-docs.md` pointing people at `docs/.templates/`. This file
  exists so anyone browsing the repo at `docs/` isn't met with a confusing
  empty directory.
- All links in `README.md` and cross-doc references point into
  `docs/.templates/...` so they work on GitHub without install.
- The install script copies `docs/.templates/*.md` to `docs/`, substitutes
  placeholders with real values via sed, and removes `looking-for-docs.md`.
- `docs/*.md` (except `looking-for-docs.md`) is gitignored — the generated
  files never get committed.

This avoids the `{{VAR}}` token problem (GitHub viewers see readable paths),
keeps a single source of truth (templates), and doesn't require any
git filter drivers or skip-worktree trickery.

## Options considered (and why rejected)

1. **Commit both templates (`.templates/foo.md` with `{{VAR}}`) and generated
   `docs/foo.md` with example paths.** Two files to edit per change. Easy to
   let them drift.

2. **Skip substitution entirely.** Simplest, but the whole point was to
   avoid users translating paths. Acceptable fallback if the template
   approach turns out to be too much machinery for one doc's worth of paths.

3. **`.gitattributes` smudge/clean filter driver.** Templates in `docs/`,
   smudge substitutes on checkout, clean reverses before commit. Technically
   correct but complex: the clean filter has to know which paths to
   un-substitute, needing the same env as install.

4. **Empty `docs/` except for `.templates/` and a signpost file.** Chosen.

## Substitutions

Placeholders in templates are plain paths/values (readable on GitHub), and
install replaces them via sed. Concrete list of replacements:

| In template                                 | Replaced with                    |
|---------------------------------------------|----------------------------------|
| `/home/you/programs/email`                  | absolute path to rmail root      |
| `/home/you/.config/rmail`                   | user's config dir                |
| `/home/you/mail`                            | user's mail dir                  |
| `/home/alice/mail`, `/home/ritz/mail`       | leave as-is (they're examples)   |

The Lua shebang in the scripting tutorial specifically becomes
`<rmail_root>/deps/lua/bin/lua` if a bundled Lua was compiled, or
`/usr/bin/env lua` otherwise.

## Install script changes

Add a function near the end of `scripts/install.sh`:

```sh
generate_docs() {
    local templates_dir="$ROOT/docs/.templates"
    local out_dir="$ROOT/docs"

    [ -d "$templates_dir" ] || return 0

    local lua_bin
    if [ -x "$ROOT/deps/lua/bin/lua" ]; then
        lua_bin="$ROOT/deps/lua/bin/lua"
    else
        lua_bin="/usr/bin/env lua"
    fi

    for tmpl in "$templates_dir"/*.md; do
        local name=$(basename "$tmpl")
        sed \
            -e "s|/home/you/programs/email/deps/lua/bin/lua|$lua_bin|g" \
            -e "s|/home/you/programs/email|$ROOT|g" \
            -e "s|/home/you/.config/rmail|$CONFIG_DIR|g" \
            -e "s|/home/you/mail|$MAIL_DIR|g" \
            "$tmpl" > "$out_dir/$name"
    done

    # remove the signpost file once real docs exist
    rm -f "$out_dir/looking-for-docs.md"
}
```

Call it after config is resolved, before the "install complete" message.

## Gitignore changes

Add to `.gitignore`:

```
# Generated docs (source of truth is docs/.templates/)
docs/*.md
!docs/looking-for-docs.md
```

`docs/.templates/` is a directory so `docs/*.md` doesn't affect it.

## signpost file

`docs/looking-for-docs.md` contains a friendly redirect pointing at
`docs/.templates/`, explaining that running `scripts/install.sh` generates
the real docs. Tone: light. It's removed during install.

## Migration

One-shot:

1. `git mv docs/*.md docs/.templates/`
2. Create `docs/looking-for-docs.md`
3. Update all links in `README.md` from `docs/foo.md` to `docs/.templates/foo.md`
4. Add `generate_docs()` to the install script and call it
5. Add gitignore rules
6. Commit templates + install + gitignore + README + signpost
7. Run install once locally to verify generation works

## Suggested Implementation Steps (2026-10-04 extension)

1. `scripts/detect-service-manager.sh`: the detection that was inline in
   `install.sh` (NixOS by `/etc/NIXOS`, then process 1's name, then which
   manager's command exists), printing one word.  `install.sh` sets
   `INIT_SYSTEM` from it.
2. `scripts/.templates/services/`: `systemd-user.service`,
   `systemd-system.service`, `runit-run`, `openrc-init`,
   `nixos-system-lua.nix`, `nixos-own-lua.nix`, copied from the inline
   blocks with the shell values replaced by `@MAILBOX@`, `@ROOT@`,
   `@CONFIG_FILE@`, `@LUA_BIN@`, `@SERVICE_LOG@`, `@SERVICE@`, `@USER@`,
   `@HOME@`, `@PORT@`.
3. `install.sh`: `fill_service_template <template> <output>` substitutes
   them (escaped with `sed_escape_replacement`) and fails if an `@NAME@`
   is left; each inline block becomes one call.
4. `docs/.templates/service.md`: fold markers round each manager's
   section.  `generate_docs` keeps the section for `INIT_SYSTEM` (all of
   them when it is `unknown`, with a line saying so);
   `generate-docs.sh` gets `INIT_SYSTEM` from the detection script, or
   from `RMAIL_SERVICE_MANAGER` to build the guide for another machine.
5. `scripts/test-service-templates.sh`: lifts `sed_escape_replacement`,
   `fill_service_template` and `generate_docs` out of `install.sh` (as
   `generate-docs.sh` does) and checks every template fills with no
   placeholder left and `| & \` intact, that an unknown placeholder
   stops the fill and leaves no file, that the guide built for each
   manager has that section only, and all four for `unknown`.  The
   byte-for-byte match with the old blocks was a one-time check while
   building, not part of the test: the old blocks no longer exist to
   compare against.

## Second extension (2026-10-04): the guide's examples are the templates

The examples in `service.md` were written by hand and had drifted from
the real files (the systemd examples lacked the log lines the installer
writes; the NixOS one lacked the log lines and the mailbox comment).
Owner, asked whether the guide should include the templates instead:
"Yeah probably."

- Each example in `docs/.templates/service.md` sits between
  `<!-- {{{ example: TEMPLATE -->` and `<!-- }}} example -->`, and is
  written there by `scripts/fill-guide-examples.lua` from
  `scripts/.templates/services/TEMPLATE`, filled with the readable
  example values the docs already use (`/home/you/programs/email`,
  `/home/you/mail`, `SERVICE-NAME`, `YOURUSER`).  So the repository's
  guide reads well, and the docs build then turns `/home/you/...` into
  this machine's real paths as it does everywhere else.
- `fill-guide-examples.lua --check` exits 1 naming any example that no
  longer matches its template; `scripts/test-service-templates.sh` runs
  it, so a template edited without re-running the tool fails the tests.
- The docs build drops the example markers along with the manager ones.

Steps: write the tool (it refuses a missing template, an unfilled
placeholder, or an example with no end marker); replace each hand
example in `service.md` with markers and run it; drop example markers in
`generate_docs`; add the check to the test.

## Status

Complete 2026-10-04, extension included.  The original work landed in
3fd6b32 (initial system + migration); every
install.sh run since then regenerates docs/*.md from the templates.
`docs/looking-for-docs.md` stays in place alongside the generated
files (no longer deleted by generate_docs — that was the one
deviation from the plan above, to keep `git status` clean after
install).
