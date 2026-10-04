#!/bin/sh
# test-renumber-issues.sh — check that renumbering issues moves the files and every mention, and nothing else
#
# scripts/renumber-issues.lua renames issue files and rewrites every
# mention of their numbers across a project.  A rewrite that touched too
# much (an HTTP 404, a longer number, a transcript) or too little (a link
# to the file, the issue's own title) would quietly damage the record, so
# this builds a small throwaway project in RAM and checks each case:
#
#   a swap            100 and 101 trade numbers: each mention lands on the
#                     right one, none is rewritten twice
#   a phase move      a completed issue moves to another phase
#   a blueprint       an unnumbered issues/new-*.md gets its number
#   kinds of mention  #100, "issue 102", a link to the file by name, the
#                     issue's own title line (with and without #)
#   left alone        #1001, #100a when only 100 moves, HTTP 404, the
#                     transcripts; a bare number after a dash is reported
#                     for a person to check, not changed
#   refusals          a number with no issue file, two issues given one
#                     number, a number already held by an issue that does
#                     not move: refused, nothing changed
#
# Usage:
#   scripts/test-renumber-issues.sh          # use the enclosing checkout
#   scripts/test-renumber-issues.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
TOOL="$DIR/scripts/renumber-issues.lua"
WORK="/tmp/rmail/tests/renumber-issues"
P="$WORK/project"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

# {{{ expect_line
# expect_line <file> <exact line> <what>
expect_line() {
    if grep -qxF -- "$2" "$1"; then ok "$3"; else note_fail "$3"; info "$(cat "$1")"; fi
}
# }}}

# {{{ build
build() {
    rm -rf "$WORK"
    mkdir -p "$P/issues/completed" "$P/docs" "$P/llm-transcripts"
    git -C "$P" init -q
    printf '# 100 - Alpha\n\nBuilds on nothing.\n' > "$P/issues/100-alpha.md"
    printf '# #101 — Beta\n\nBuilds on #100, not #1001 or #100a.\n' > "$P/issues/101-beta.md"
    printf '# #100a — Alpha part one\n\nPart of #100.\n' > "$P/issues/100a-alpha-part-one.md"
    printf '# #102 — Gamma\n\nDone.\n' > "$P/issues/completed/102-gamma.md"
    printf '# #new-delta — Delta\n\nNeeds #101.\n' > "$P/issues/new-delta.md"
    cat > "$P/docs/guide.md" <<'DOC'
See #100 and #101, and issue 102.
The blueprint #new-delta, not #new-deltas, and its file new-delta.md.
The blueprint: issues/101-beta.md, and issues/completed/102-gamma.md.
The server answers HTTP 404 when it has nothing.
Ranges: #100–101 were one piece of work.
DOC
    printf 'we talked about #100 today\n' > "$P/llm-transcripts/talk.md"
    cp "$P/llm-transcripts/talk.md" "$WORK/talk.before"
}
# }}}

echo ""
echo "rmail renumber-issues test"
echo "  tool:    $TOOL"
echo "  scratch: $WORK"

build
printf '# a swap, a phase move, a blueprint\n100 101\n101 100\n102 205\nnew-delta 103\n' > "$WORK/map"
"$TOOL" "$P" "$WORK/map" > "$WORK/out" 2>&1
status=$?

echo ""
echo "the files"
[ "$status" -eq 0 ] && ok "the tool finished" || { note_fail "the tool stopped with $status"; info "$(cat "$WORK/out")"; }
[ -f "$P/issues/101-alpha.md" ] && [ -f "$P/issues/100-beta.md" ] && ok "100 and 101 swapped files" || note_fail "the swap did not move both files"
[ -f "$P/issues/completed/205-gamma.md" ] && ok "the completed issue moved to phase 2, staying in completed/" || note_fail "205-gamma.md missing"
[ -f "$P/issues/103-delta.md" ] && ok "the blueprint got its number" || note_fail "103-delta.md missing"
[ -f "$P/issues/100a-alpha-part-one.md" ] && ok "a sub-issue not in the mapping kept its number" || note_fail "100a moved"
ls "$P/issues/"*.renumbering >/dev/null 2>&1 && note_fail "a half-renamed file was left" || ok "no half-renamed file left"

echo ""
echo "the mentions"
expect_line "$P/issues/101-alpha.md" "# 101 - Alpha" "a title line with no # follows its file"
expect_line "$P/issues/100-beta.md" "# #100 — Beta" "a title line with # follows its file"
expect_line "$P/issues/100-beta.md" "Builds on #101, not #1001 or #100a." "#100 became #101; #1001 and #100a were left alone"
expect_line "$P/issues/103-delta.md" "Needs #100." "a mention in the blueprint followed the swap"
expect_line "$P/issues/103-delta.md" "# #103 — Delta" "the blueprint's own title got its number"
expect_line "$P/docs/guide.md" "The blueprint #103, not #new-deltas, and its file 103-delta.md." "#new-name became the number; a longer name and the file name were handled apart"
expect_line "$P/docs/guide.md" "See #101 and #100, and issue 205." "#number and 'issue number' were rewritten, each once"
expect_line "$P/docs/guide.md" "The blueprint: issues/100-beta.md, and issues/completed/205-gamma.md." "links by file name were rewritten"
expect_line "$P/docs/guide.md" "The server answers HTTP 404 when it has nothing." "an HTTP 404 was left alone"
if cmp -s "$P/llm-transcripts/talk.md" "$WORK/talk.before"; then ok "the transcript was not touched"; else note_fail "the transcript was rewritten"; fi
if grep -q "docs/guide.md:5 (101)" "$WORK/out"; then
    ok "the bare number in a range was reported for a person to check"
else
    note_fail "the range was not reported"; info "$(cat "$WORK/out")"
fi
expect_line "$P/docs/guide.md" "Ranges: #101–101 were one piece of work." "and only its #-number was changed"

echo ""
echo "refusals"
for case in "missing:999 300" "twice:100 300
101 300" "held:100 102"; do
    name="${case%%:*}"; lines="${case#*:}"
    build
    printf '%s\n' "$lines" > "$WORK/map"
    find "$P" -path "$P/.git" -prune -o -type f -print | sort | xargs md5sum > "$WORK/before.sum"
    "$TOOL" "$P" "$WORK/map" > "$WORK/out" 2>&1
    st=$?
    find "$P" -path "$P/.git" -prune -o -type f -print | sort | xargs md5sum > "$WORK/after.sum"
    if [ "$st" -ne 0 ] && cmp -s "$WORK/before.sum" "$WORK/after.sum"; then
        ok "$name: refused, nothing changed ($(grep -v '^refused' "$WORK/out" | head -1 | sed 's/^ *//'))"
    else
        note_fail "$name: not refused cleanly (status $st)"; info "$(cat "$WORK/out")"
    fi
done

echo ""
echo "a dry run"
build
printf '100 300\n' > "$WORK/map"
find "$P" -path "$P/.git" -prune -o -type f -print | sort | xargs md5sum > "$WORK/before.sum"
"$TOOL" "$P" "$WORK/map" --dry-run > "$WORK/out" 2>&1
find "$P" -path "$P/.git" -prune -o -type f -print | sort | xargs md5sum > "$WORK/after.sum"
if cmp -s "$WORK/before.sum" "$WORK/after.sum" && grep -q "would change" "$WORK/out"; then
    ok "it says what it would do and changes nothing"
else
    note_fail "the dry run changed something"
fi

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
