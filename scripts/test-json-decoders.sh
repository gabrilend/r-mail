#!/bin/sh
# test-json-decoders.sh — check that the JSON library's two decoders agree,
# and that the library really uses the faster one whenever it can
#
# rmail keeps all of its state (the .state/*.json files) and every message
# on the wire as JSON, read through the bundled library libs/dkjson.lua.
# That library carries two decoders: one in plain Lua, and one built on
# LPeg, a C library for matching text that is faster on large inputs.  It
# picks one by itself when it loads.  Until 2026-09-29 (issue #403) its
# check for LPeg crashed on every modern LPeg and it fell back to plain Lua
# without a word; this test exists so that can never go unnoticed again.
#
# For every Lua interpreter found on this machine, the script:
#
#   agree        decodes a fixed set of texts shaped like rmail's real
#                state files through both decoders and compares the results
#                field by field — including number kinds and which empty
#                tables are objects and which are arrays
#   switch       if LPeg can be loaded by that interpreter, fails unless the
#                library actually switched to it
#   old-lpeg     pretends LPeg is an old one whose version is a function
#                returning "0.12": the library must still switch to it
#   refuse-0.11  pretends LPeg is the buggy 0.11: the library must refuse it
#                and say so
#
# An interpreter with no LPeg gets the plain decoder checked against its
# own expectations only, and is reported as "skip" for the LPeg rows — a
# skip is not a pass.
#
# Usage:
#   scripts/test-json-decoders.sh                  # use the enclosing checkout
#   scripts/test-json-decoders.sh /path            # use some other checkout
#   scripts/test-json-decoders.sh /path /mailbox   # also decode that mailbox's
#                                                  # real .state/*.json files
#                                                  # through both decoders
#
# Exit status is 0 when nothing failed, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
MAILBOX="${2:-}"

LIBS="$DIR/libs"

# RAM-backed scratch space for the generated Lua checker, per project
# convention.  Rebuilt every run so an old checker can never be the one run.
WORK="/tmp/rmail/tests/json-decoders"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

FAILURES=0

echo ""
echo "rmail json-decoder test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"
[ -n "$MAILBOX" ] && echo "  mailbox:  $MAILBOX"
echo ""

if [ ! -f "$LIBS/dkjson.lua" ]; then
    fail "no JSON library at $LIBS/dkjson.lua"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK"

# ---- the checker, run once per interpreter ---------------------------------
#
# Arguments: <libs dir> [state file ...].  Prints one line per check, each
# starting with "ok", "--" (failed) or "skip", and exits with the number of
# failures (0 when all passed).
cat > "$WORK/check.lua" <<'EOF'
local libs = arg[1]
package.path = libs .. "/?.lua;" .. package.path

local failures = 0
local function ok(s)   print("ok   " .. s) end
local function bad(s)  print("--   " .. s); failures = failures + 1 end
local function skip(s) print("skip " .. s) end

-- Texts shaped like the files rmail keeps in .state/ (see load_state and
-- save_state users in rmail.lua).  Values are made up; the shapes are real.
-- Edge cases a decoder is most likely to disagree on are mixed in: empty
-- object vs empty array, escapes, surrogate pairs, number kinds, null.
local FIXTURES = {
  ["inbox.json"] = [[{
    "dinosaur-hoodie-pic":{"message_id":"3dec8347-68c4-4f1c-a092-a5e80c0c6b54","from":"alice"},
    "photo.jpg-consent-to-download-form":{"from":"alice",
      "message_id":"consent-09f21778-b302-4ce6-8f23-af24ed665885",
      "consent":"09f21778-b302-4ce6-8f23-af24ed665885"}
  }]],
  ["outbox.json"] = [[{
    "notes-for-later":{"recipients":{"alice":{"message_id":"c7d6a088-5df6-4817-a921-8df2bc0b4a8c"},
                                     "bob":{"message_id":"78e4242d-a715-4106-ba6e-a99933d30e03"}},
      "body_checksum":"03aeccfb3dd92b13a793be6e0add3f64df4f31d60b2dad838bace3bf9ba4914b"}
  }]],
  ["consent-pending.json"] = [[{
    "09f21778-b302-4ce6-8f23-af24ed665885":{"inbox_file":"photo.jpg-consent-to-download-form",
      "status":"receiving","start_time":1790183576,"message_id":"3dec8347",
      "filename":"photo.jpg","from":"alice","expected_size":1424049}
  }]],
  ["consent-responses.json (empty)"] = "[]",
  ["consent-responses.json"] = [==[[{"consent_id":"a1","answer":"accept","to":"bob"},
                                   {"consent_id":"b2","answer":"deny","to":"alice"}]]==],
  ["chunks-outgoing.json (empty)"] = "{\n}\n",
  ["uploads.json"] = [[{"fd12c569":{"path":"/home/someone/mail/attachments/.uploads/fd12c569/pic one.jpg",
      "num_chunks":1,"created_at":1775598683,"filename":"pic one.jpg",
      "upload_dir":"/home/someone/mail/attachments/.uploads/fd12c569","chunks_done":[]}}]],
  ["pending-address.json"] = [[{"alice":{"ip":"203.0.113.7","port":8025},
                                "bob":{"ip":"2001:db8::1","port":8026}}]],
  ["nat_mapping.json"] = [[{"external_port":8025,"internal_port":8025,"lifetime":7200,
                            "method":"upnp","ok":true,"renewed":false,"note":null}]],
  ["escapes and numbers"] = [==[{"quote":"say \"hi\"","slash":"a\\b\/c","lines":"one\ntwo\ttab",
      "accent":"café","emoji":"😀","raw_utf8":"héllo",
      "ints":[0,-1,42,9007199254740991],"floats":[1.5,-0.25,1e3,2.5E-2],
      "nested":[[],{},[[]],{"a":{}}]}]==],
}

-- Deep comparison.  Tables must have the same keys, the same values, and
-- the same JSON kind (dkjson marks decoded tables "object" or "array" in a
-- metatable; that is how an empty {} and an empty [] stay different when
-- written back out).  Numbers must also be the same kind (integer or float)
-- on Lua versions that have two kinds.
local function same(a, b, where)
  if type(a) ~= type(b) then return false, where .. ": " .. type(a) .. " vs " .. type(b) end
  if type(a) == "number" then
    if math.type and math.type(a) ~= math.type(b) then
      return false, where .. ": number kinds " .. math.type(a) .. " vs " .. math.type(b)
    end
    if a ~= b then return false, where .. ": " .. tostring(a) .. " vs " .. tostring(b) end
    return true
  end
  if type(a) ~= "table" then
    if a ~= b then return false, where .. ": " .. tostring(a) .. " vs " .. tostring(b) end
    return true
  end
  local ka = getmetatable(a) and getmetatable(a).__jsontype
  local kb = getmetatable(b) and getmetatable(b).__jsontype
  if ka ~= kb then return false, where .. ": kind " .. tostring(ka) .. " vs " .. tostring(kb) end
  for k, v in pairs(a) do
    local good, why = same(v, b[k], where .. "." .. tostring(k))
    if not good then return false, why end
  end
  for k in pairs(b) do
    if a[k] == nil then return false, where .. "." .. tostring(k) .. ": missing on the left" end
  end
  return true
end

-- Load a fresh copy of the library, with LPeg supplied by `lpeg_loader`:
-- nil lets Lua find the real one (if any); a function replaces it.
local function fresh_dkjson(lpeg_loader)
  package.loaded.dkjson = nil
  package.loaded.lpeg = nil
  package.preload.lpeg = lpeg_loader
  local json = require("dkjson")
  package.preload.lpeg = nil
  return json
end

-- Can this interpreter load the real LPeg?  Loaded once and kept, so the
-- stand-ins below can wrap it.
local real_lpeg_ok, real_lpeg = pcall(require, "lpeg")
package.loaded.lpeg = nil

local plain = fresh_dkjson(function() error("hidden by the test") end)
if plain.using_lpeg then
  bad("plain: library claims LPeg although LPeg was hidden")
elseif not tostring(plain.lpeg_unused_reason):find("hidden by the test", 1, true) then
  bad("plain: the reason LPeg is unused was not kept (got " .. tostring(plain.lpeg_unused_reason) .. ")")
else
  ok("plain: on the plain decoder, and it says why")
end

local natural = fresh_dkjson(nil)

-- switch: LPeg present means LPeg used; anything else is the silent
-- fallback this test exists to catch.
if real_lpeg_ok then
  local v = real_lpeg.version
  if type(v) == "function" then v = v() end
  if natural.using_lpeg then
    ok("switch: " .. tostring(v) .. " is present and in use")
  else
    bad("switch: " .. tostring(v) .. " is present but unused: " .. tostring(natural.lpeg_unused_reason))
  end
else
  skip("switch: LPeg is not installed for " .. _VERSION)
end

-- agree: every fixture through both decoders.  Without LPeg, "natural" is
-- also the plain decoder, so this only proves the plain decoder reads them.
local function compare_text(name, text)
  local a, _, erra = plain.decode(text)
  local b, _, errb = natural.decode(text)
  if a == nil or b == nil then
    bad("agree: " .. name .. " did not decode (plain: " .. tostring(erra) .. ", other: " .. tostring(errb) .. ")")
    return
  end
  local good, why = same(a, b, name)
  if good then ok("agree: " .. name) else bad("agree: " .. why) end
end

local names = {}
for name in pairs(FIXTURES) do names[#names + 1] = name end
table.sort(names)
for _, name in ipairs(names) do compare_text(name, FIXTURES[name]) end

-- Real state files named on the command line.
for i = 2, #arg do
  local fh = io.open(arg[i], "rb")
  if not fh then
    bad("agree: cannot read " .. arg[i])
  else
    local text = fh:read("*a")
    fh:close()
    compare_text(arg[i], text)
  end
end

-- Both decoders must refuse broken text.  Their messages differ; only the
-- refusal is compared.
do
  local broken = '{"from":"alice",'
  local a = plain.decode(broken)
  local b = natural.decode(broken)
  if a == nil and b == nil then ok("agree: both refuse a cut-off text")
  else bad("agree: a cut-off text was accepted by one decoder") end
end

-- old-lpeg and refuse-0.11 use stand-ins built on the real LPeg: a copy of
-- its table with `version` swapped for a function, as LPeg 0.x had it.
if real_lpeg_ok then
  local function lpeg_claiming(ver)
    return function()
      local copy = {}
      for k, v in pairs(real_lpeg) do copy[k] = v end
      copy.version = function() return ver end
      return copy
    end
  end
  local old = fresh_dkjson(lpeg_claiming("0.12"))
  if old.using_lpeg then ok("old-lpeg: a function-style version is still accepted")
  else bad("old-lpeg: refused: " .. tostring(old.lpeg_unused_reason)) end

  local buggy = fresh_dkjson(lpeg_claiming("0.11"))
  if buggy.using_lpeg then
    bad("refuse-0.11: the buggy LPeg 0.11 was used")
  elseif tostring(buggy.lpeg_unused_reason):find("0.11", 1, true) then
    ok("refuse-0.11: refused, and the reason names 0.11")
  else
    bad("refuse-0.11: refused for another reason: " .. tostring(buggy.lpeg_unused_reason))
  end
else
  skip("old-lpeg: needs a real LPeg to stand in for")
  skip("refuse-0.11: needs a real LPeg to stand in for")
end

os.exit(failures == 0 and 0 or 1)
EOF

# ---- which interpreters ----------------------------------------------------
#
# The bundled one first (run-rmail.sh's first choice), then run-rmail.sh's
# fallbacks, then plain "lua".  The same binary under two names is run once.
CANDIDATES="$DIR/deps/lua/bin/lua lua5.4 luajit lua5.3 lua5.2 lua5.1 lua"
SEEN=""

STATE_FILES=""
if [ -n "$MAILBOX" ]; then
    for f in "$MAILBOX"/.state/*.json; do
        [ -f "$f" ] && STATE_FILES="$STATE_FILES $f"
    done
    [ -z "$STATE_FILES" ] && info "no .state/*.json files under $MAILBOX"
fi

RAN=0
for cand in $CANDIDATES; do
    bin="$(command -v "$cand")" || continue
    real="$(readlink -f "$bin")"
    case " $SEEN " in *" $real "*) continue ;; esac
    SEEN="$SEEN $real"
    RAN=$((RAN + 1))

    version="$("$bin" -v 2>&1 | head -n 1)"
    echo "$cand  ($version)"
    # $STATE_FILES is split on spaces on purpose; mailbox paths with spaces
    # in them are not supported by this option.
    # shellcheck disable=SC2086
    output="$("$bin" "$WORK/check.lua" "$LIBS" $STATE_FILES 2>&1)"
    status=$?
    printf "%s\n" "$output" | while IFS= read -r line; do
        case "$line" in
            "ok   "*)   ok   "${line#ok   }" ;;
            "--   "*)   fail "${line#--   }" ;;
            "skip "*)   info "skip: ${line#skip }" ;;
            *)          fail "$line" ;;
        esac
    done
    if [ $status -ne 0 ]; then
        FAILURES=$((FAILURES + 1))
    fi
    echo ""
done

if [ $RAN -eq 0 ]; then
    fail "no Lua interpreter found"
    exit 1
fi

if [ $FAILURES -eq 0 ]; then
    echo "all interpreters passed ($RAN run)"
    exit 0
fi
echo "$FAILURES of $RAN interpreter(s) had failures"
exit 1
