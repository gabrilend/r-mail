# Treat docs/ as build artifacts generated from docs/.templates/

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

## Status

Complete.  Landed in 3fd6b32 (initial system + migration); every
install.sh run since then regenerates docs/*.md from the templates.
`docs/looking-for-docs.md` stays in place alongside the generated
files (no longer deleted by generate_docs — that was the one
deviation from the plan above, to keep `git status` clean after
install).
