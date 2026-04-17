#!/bin/sh
# drive-common.sh — shared helpers for make-installer-drive.sh and
# make-mailbox-drive.sh.  Sourced, not executed.
#
# Provides:
#   drive_detect   — find a mounted flash drive whose label matches $FLASH_LABEL
#                    (or whose mount-point basename matches it).  Writes the
#                    resolved mount point to stdout.  Exits non-zero with a
#                    message on zero or multiple matches.
#   drive_eject_hint — print the exact unmount command for a given path.
#
# Callers set FLASH_LABEL before sourcing this file.

# ---------------------------------------------------------------------------
# Colour helpers.  Mirror install.sh so the drive generators feel familiar.
info()  { printf "  %s\n" "$*"; }
warn()  { printf "  \033[33m%s\033[0m\n" "$*"; }
ok()    { printf "  \033[32m%s\033[0m\n" "$*"; }
err()   { printf "  \033[31merror: %s\033[0m\n" "$*" >&2; }

# ---------------------------------------------------------------------------
# drive_detect — echoes the mount point of the flash drive, or exits 1.
#
# Strategy: enumerate mount points via /proc/mounts, keep entries whose mount
# path basename equals $FLASH_LABEL.  That covers the common auto-mount
# layouts (/run/media/$USER/$LABEL, /media/$USER/$LABEL, /media/$LABEL)
# without needing root or lsblk-specific flags.
drive_detect() {
    if [ -z "${FLASH_LABEL:-}" ]; then
        err "FLASH_LABEL is not set"
        exit 1
    fi

    # Collect candidate mount points.  /proc/mounts is the most reliable
    # source across distros; awk field 2 is the mount point.
    _matches=""
    _count=0
    while IFS= read -r _mp; do
        if [ "$(basename "$_mp")" = "$FLASH_LABEL" ]; then
            _matches="$_matches$_mp
"
            _count=$((_count + 1))
        fi
    done <<EOF
$(awk '{print $2}' /proc/mounts 2>/dev/null | sort -u)
EOF

    if [ "$_count" -eq 0 ]; then
        err "no mounted flash drive named '$FLASH_LABEL' found"
        err "  expected a drive labelled '$FLASH_LABEL' auto-mounted under"
        err "  /run/media/\$USER/, /media/\$USER/, or /media/."
        err "  pass --dest <path> to override auto-detection."
        exit 1
    fi

    if [ "$_count" -gt 1 ]; then
        err "multiple drives labelled '$FLASH_LABEL' are mounted:"
        printf '%s' "$_matches" | while IFS= read -r _m; do
            [ -n "$_m" ] && err "    $_m"
        done
        err "  pass --dest <path> to pick one."
        exit 1
    fi

    # Strip the trailing newline introduced by the accumulator.
    printf '%s' "$_matches" | sed '/^$/d'
}

# drive_eject_hint PATH — print a suggested unmount command.  Doesn't run it.
drive_eject_hint() {
    _path="$1"
    info "when you're done:"
    info "    sync && udisksctl unmount -b \"\$(findmnt -no SOURCE '$_path')\""
    info "  or, if udisksctl isn't available:"
    info "    sync && sudo umount '$_path'"
}

# drive_confirm_writable PATH — sanity-check that the destination is writable.
drive_confirm_writable() {
    _path="$1"
    if [ ! -d "$_path" ]; then
        err "destination is not a directory: $_path"
        exit 1
    fi
    if [ ! -w "$_path" ]; then
        err "destination is not writable: $_path"
        err "  (check mount options or run as the mount owner)"
        exit 1
    fi
}
