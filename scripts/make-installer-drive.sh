#!/bin/sh
# make-installer-drive.sh — populate a USB drive with a portable rmail installer.
#
# Implements issue #361.  The resulting drive looks like:
#
#   /install.sh       # thin wrapper that execs source-code/scripts/install.sh
#   /README.md        # "plug in, run ./install.sh" instructions
#   /source-code/     # full rmail source tree (minus build artefacts)
#
# A user plugs the drive into any Linux/macOS host, reads README.md, and
# runs ./install.sh to install rmail on that host.  The resulting rmail
# install lives wherever the user points --mail-dir at, same as a normal
# clone-and-install.  The drive is only a distribution medium.
#
# Usage:
#   scripts/make-installer-drive.sh [--dest PATH] [--dry-run] [--include-libs]
#
# The drive is auto-detected by filesystem label (see FLASH_LABEL below) —
# all of our target flash drives should use the same label.  --dest overrides
# auto-detection (useful in CI or when the label convention isn't followed).

set -e

# ---------------------------------------------------------------------------
# Configuration — tweak once, then forget.
FLASH_LABEL="RMAIL"

# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

. "$SCRIPT_DIR/lib/drive-common.sh"

DRY_RUN=false
DEST=""
INCLUDE_LIBS=false

show_help() {
    cat <<'HELP'
Usage: make-installer-drive.sh [options]

Options:
  -h, --help         Show this help and exit
  --dest PATH        Write to PATH instead of auto-detecting a flash drive
  --dry-run          Print what would be copied; don't modify anything
  --include-libs     Include prebuilt libs/ and deps/ on the drive.  Skipped
                     by default because prebuilt binaries rarely match an
                     arbitrary host's glibc/arch — install.sh rebuilds them
                     cleanly on the target.  Use only when shipping to a
                     known identical host.

Auto-detection looks for a mounted filesystem whose mount-point basename
matches the FLASH_LABEL at the top of this script (currently "RMAIL").
If zero or multiple drives match, --dest is required.
HELP
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) show_help; exit 0 ;;
        --dest)
            if [ -z "${2:-}" ]; then err "--dest requires a path"; exit 1; fi
            DEST="$2"; shift 2
            ;;
        --dest=*) DEST="${1#*=}"; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --include-libs) INCLUDE_LIBS=true; shift ;;
        *) err "unknown argument: $1"; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Resolve destination.

if [ -z "$DEST" ]; then
    DEST=$(drive_detect)
    ok "detected flash drive: $DEST"
else
    info "using explicit destination: $DEST"
fi

if ! $DRY_RUN; then
    drive_confirm_writable "$DEST"
fi

# Refuse to write into the source tree itself — easy footgun.
_root_real=$(cd "$ROOT" && pwd -P)
_dest_real=$(cd "$DEST" 2>/dev/null && pwd -P || echo "$DEST")
case "$_dest_real" in
    "$_root_real"|"$_root_real"/*)
        err "destination is inside the source tree: $DEST"
        err "  pick a different path — writing here would clobber the repo."
        exit 1
        ;;
esac

# ---------------------------------------------------------------------------
# rsync the source tree into source-code/ on the drive.

info "populating $DEST/source-code/ from $ROOT"

RSYNC_FLAGS="-a --delete --human-readable"
if $DRY_RUN; then
    RSYNC_FLAGS="$RSYNC_FLAGS --dry-run --itemize-changes"
fi

# Exclude list.  Build artefacts, VCS, editor junk, local state that might
# accidentally live in the developer's tree.
RSYNC_EXCLUDES="
--exclude=.git/
--exclude=.gitignore
--exclude=.build-tmp/
--exclude=.logs/
--exclude=.claude/
--exclude=.vscode/
--exclude=.idea/
--exclude=.DS_Store
--exclude=*.swp
--exclude=*.swo
--exclude=__pycache__/
--exclude=mailbox-*/
--exclude=.state/
--exclude=**/build/
--exclude=.gradle/
--exclude=*.apk
--exclude=*.aab
"

if ! $INCLUDE_LIBS; then
    RSYNC_EXCLUDES="$RSYNC_EXCLUDES
--exclude=libs/
--exclude=deps/
--exclude=*.o
--exclude=*.so
"
fi

# shellcheck disable=SC2086  # we want word-splitting on the flag lists
mkdir -p "$DEST/source-code"
rsync $RSYNC_FLAGS $RSYNC_EXCLUDES "$ROOT/" "$DEST/source-code/"

if $DRY_RUN; then
    ok "dry run complete — nothing written."
    exit 0
fi

# ---------------------------------------------------------------------------
# Write the top-level install.sh wrapper.

cat > "$DEST/install.sh" <<'WRAPPER'
#!/bin/sh
# install.sh — portable rmail installer.
#
# This is a thin wrapper that hands off to the real installer inside the
# source-code/ directory on this drive.  Pass any install.sh flag you like;
# they're forwarded unchanged.  Run `./install.sh --help` for the full list.

set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
exec "$HERE/source-code/scripts/install.sh" "$@"
WRAPPER
chmod +x "$DEST/install.sh"

# ---------------------------------------------------------------------------
# Write the top-level README.md.

cat > "$DEST/README.md" <<'README'
# Portable rmail installer

This USB drive installs rmail — a file-based encrypted messaging daemon —
onto a Linux or macOS host.  The drive itself is only a distribution medium;
rmail runs on the host after install, not on the drive.

## Quick start

1. Plug the drive in.  It should auto-mount; if it doesn't, mount it
   manually (the contents are read-only at rest, so mounting rw is fine).
2. Open a terminal at the drive's mount point.
3. Run the installer:

       ./install.sh

   The installer will ask a few questions (mailbox location, identity,
   port) and then build rmail's dependencies from source.  First-time
   install takes a few minutes on most hosts.

4. When it's done, it'll print a summary with paths and next steps.

## Unattended install

Every prompt has a matching CLI flag.  See `./install.sh --help` for the
full list.  A fully non-interactive install looks like:

    ./install.sh --silent --yes \
        --mail-dir=$HOME/mail --name=alice --port=54321

## Troubleshooting

* **"no C compiler found"** — install gcc or clang through the host's
  package manager (e.g. `sudo apt install build-essential` on Debian /
  Ubuntu) and re-run.
* **The installer fails mid-build** — re-run; every phase is reentrant
  and skips work that's already done.  Add `--force` to rebuild from
  scratch.

## What's on the drive?

* `install.sh` — this wrapper.  Hands off to `source-code/scripts/install.sh`.
* `source-code/` — the full rmail source tree.  You can copy this out
  after install if you want to hack on rmail itself; the installed daemon
  runs from wherever you copied it.
* `README.md` — this file.
README

# ---------------------------------------------------------------------------
# Summary.

_bytes=$(du -sh "$DEST" 2>/dev/null | awk '{print $1}')
echo ""
ok "installer drive ready at $DEST (total size: ${_bytes:-unknown})"
info "drive contents:"
info "    $DEST/install.sh"
info "    $DEST/README.md"
info "    $DEST/source-code/  (rmail source)"
echo ""
drive_eject_hint "$DEST"
