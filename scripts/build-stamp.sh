#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later WITH AdditionRef-rmail-hook-exception
# Copyright (C) 2026 ritz.  See LICENSE for the terms and the hook-script permission.
#
# build-stamp.sh — write the stamp naming the source a tree holds (#615)
#
# A running daemon answers a contact's GET /source with what it is: the
# revision this stamp claims, the digest the stamp recorded, and the digest
# of the files it actually read.  This script writes the claim.
#
# usage: scripts/build-stamp.sh [--by NAME] [--revision-from DIR] TREE
#        scripts/build-stamp.sh --digest TREE
#
#   TREE             the folder holding rmail.lua; the stamp is written to
#                    TREE/build-stamp
#   --by             what is stamping, recorded as `by` (default: build-stamp.sh)
#   --revision-from  the checkout to ask git about (default: TREE).  A
#                    drive's program is a copy, so its generator names the
#                    checkout it copied from.
#   --digest         print the digest of TREE and write nothing
#
# The stamp, `key = value` lines:
#   revision = `git describe --always --dirty` of the checkout, when the
#              folder is a git checkout's own top.  Otherwise the revision
#              of the stamp already there, kept only while the files still
#              have the digest it recorded; when they changed, "unknown,
#              changed since <that revision>", so a stamp copied onto a
#              tree that was then edited stops vouching for it.  With
#              neither, "unknown".
#   digest   = sha-256 over one line per file, "<sha-256>  <path>", in the
#              order below.  rmail.lua computes the same (identity.FILES);
#              scripts/test-build-identity.sh checks the lists agree.
#   by       = what wrote it
#
# No time is recorded: two kinds of machine built from one checkout must
# carry the same stamp (make-mailbox-drive.sh refuses payloads that differ
# in anything but their compiled parts).

set -u

# rmail's own Lua, in this order -- the same list as identity.FILES in rmail.lua
FILES="rmail.lua libs/dkjson.lua libs/zip-compat.lua libs/zip-inflate.lua libs/zip-reader.lua libs/zip-writer.lua"

err() { echo "build-stamp.sh: $*" >&2; }

# sha256 of standard input, as bare hex
sha() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 | cut -d' ' -f1
    elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 | sed 's/^.*= *//'
    else err "no sha256sum, shasum or openssl to hash with"; return 1
    fi
}

manifest() {
    for _f in $FILES; do
        if [ -f "$1/$_f" ]; then
            _h=$(sha < "$1/$_f") || return 1
        else
            _h=absent
        fi
        printf '%s  %s\n' "$_h" "$_f"
    done
}

digest() {
    _m=$(manifest "$1") || return 1
    printf '%s\n' "$_m" | sha
}

BY=build-stamp.sh
FROM=""
ONLY_DIGEST=false
TREE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --by) [ $# -ge 2 ] || { err "--by needs a name"; exit 2; }; BY=$2; shift 2 ;;
        --revision-from) [ $# -ge 2 ] || { err "--revision-from needs a folder"; exit 2; }; FROM=$2; shift 2 ;;
        --digest) ONLY_DIGEST=true; shift ;;
        -h|--help) sed -n '5,36p' "$0"; exit 0 ;;
        -*) err "unknown option: $1"; exit 2 ;;
        *) [ -z "$TREE" ] || { err "one tree only"; exit 2; }; TREE=$1; shift ;;
    esac
done
[ -n "$TREE" ] || { err "name the tree holding rmail.lua"; exit 2; }
[ -d "$TREE" ] || { err "not a folder: $TREE"; exit 2; }
TREE=$(cd "$TREE" && pwd -P)
[ -f "$TREE/rmail.lua" ] || { err "no rmail.lua in $TREE"; exit 2; }
[ -n "$FROM" ] || FROM=$TREE

DIGEST=$(digest "$TREE") || exit 1
if $ONLY_DIGEST; then echo "$DIGEST"; exit 0; fi

# The revision: git, but only when FROM is a checkout's own top.  A folder
# inside some other repository (a drive kept in a dotfiles repo) would
# otherwise be stamped with that repository's commit.
REVISION=""
if [ -d "$FROM" ] && command -v git >/dev/null 2>&1; then
    _top=$(git -C "$FROM" rev-parse --show-toplevel 2>/dev/null) || _top=""
    if [ -n "$_top" ] && [ "$(cd "$_top" && pwd -P)" = "$(cd "$FROM" && pwd -P)" ]; then
        REVISION=$(git -C "$FROM" describe --always --dirty --abbrev=12 2>/dev/null) || REVISION=""
    fi
fi
if [ -z "$REVISION" ] && [ -f "$TREE/build-stamp" ]; then
    _old_rev=$(sed -n 's/^revision *= *//p' "$TREE/build-stamp" | head -n 1)
    _old_dig=$(sed -n 's/^digest *= *//p' "$TREE/build-stamp" | head -n 1)
    if [ -n "$_old_rev" ] && [ "$_old_dig" = "$DIGEST" ]; then
        REVISION=$_old_rev
    elif [ -n "$_old_rev" ]; then
        case "$_old_rev" in
            "unknown, changed since "*) REVISION=$_old_rev ;;
            *) REVISION="unknown, changed since $_old_rev" ;;
        esac
    fi
fi
[ -n "$REVISION" ] || REVISION=unknown

_tmp="$TREE/build-stamp.tmp.$$"
{
    echo "# what source this rmail is (#615), written by scripts/build-stamp.sh"
    echo "revision = $REVISION"
    echo "digest = $DIGEST"
    echo "by = $BY"
} > "$_tmp" && mv "$_tmp" "$TREE/build-stamp" || { rm -f "$_tmp"; err "could not write $TREE/build-stamp"; exit 1; }
echo "$REVISION $DIGEST"
