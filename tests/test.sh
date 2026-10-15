#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.."
KC="$PWD/kc"
PW="kctestpw"
FAIL=0

mkkc() {
    local kc="/tmp/kc-test-$1-$$.keychain-db"
    security create-keychain -p "$PW" "$kc" >/dev/null
    security unlock-keychain -p "$PW" "$kc" >/dev/null
    echo "$kc"
}
KEYCHAINS=()
cleanup() { for k in "${KEYCHAINS[@]:-}"; do security delete-keychain "$k" 2>/dev/null; done; }
trap cleanup EXIT

ok()   { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; FAIL=1; }

expect_exit() { # expected actual desc
    if [ "$2" -eq "$1" ]; then ok "$3 (exit $1)"; else fail "$3 (want $1, got $2)"; fi
}

# --- Test 1: 4000-char secret via stdin, readable by security(1) ---
KC1=$(mkkc 1); KEYCHAINS+=("$KC1")
SECRET=$(python3 -c "import random,string;print(''.join(random.choices(string.ascii_letters+string.digits,k=4000)),end='')")
printf '%s' "$SECRET" | "$KC" set -s t1svc -a t1acct -k "$KC1"
expect_exit 0 $? "t1: set 4000-char secret"
GOT=$("$KC" get -s t1svc -a t1acct -k "$KC1")
if [ "$GOT" = "$SECRET" ]; then ok "t1: kc get round-trip"; else fail "t1: kc get round-trip"; fi
GOT2=$(security find-generic-password -s t1svc -a t1acct -w "$KC1")
if [ "$GOT2" = "$SECRET" ]; then ok "t1: security(1) reads it (trusted ACL)"; else fail "t1: security(1) read"; fi

# --- Test 2: interactive pty prompt ---
KC2=$(mkkc 2); KEYCHAINS+=("$KC2")
PTY="tests/pty_input.py"
hexof() { printf '%s' "$1" | python3 -c 'import sys;print(sys.stdin.buffer.read().hex())'; }

# 2a: 4000-char secret (exceeds the 1024-byte MAX_CANON canonical limit)
S4000=$(python3 -c "import random,string;print(''.join(random.choices(string.ascii_letters+string.digits,k=4000)),end='')")
S4H=$(hexof "$S4000")
python3 "$PTY" "$KC" "$KC2" t2svc t2acct "$S4H" "$S4H"
expect_exit 0 $? "t2: interactive set of 4000-char secret"
GOT=$("$KC" get -s t2svc -a t2acct -k "$KC2")
if [ "$GOT" = "$S4000" ]; then ok "t2: 4000-char round-trip via pty"; else fail "t2: 4000-char pty (got ${#GOT} chars)"; fi

# 2b: backspace editing: "abcX\x7fd" -> "abcd"
BS=$(python3 -c "print('abcX\x7fd'.encode().hex())")
python3 "$PTY" "$KC" "$KC2" t2bs t2acct "$BS" "$BS"
expect_exit 0 $? "t2: interactive set with backspace"
[ "$("$KC" get -s t2bs -a t2acct -k "$KC2")" = "abcd" ] && ok "t2: backspace produces abcd" || fail "t2: backspace (got '$("$KC" get -s t2bs -a t2acct -k "$KC2")')"

# 2c: mismatched retype
python3 "$PTY" "$KC" "$KC2" t2mm a 616161 626262
expect_exit 1 $? "t2: mismatched retype exits 1"
"$KC" get -s t2mm -a a -k "$KC2" >/dev/null 2>&1
expect_exit 44 $? "t2: nothing stored on mismatch"

# --- Test 3: trailing newline handling ---
KC3=$(mkkc 3); KEYCHAINS+=("$KC3")
printf 'abc\n' | "$KC" set -s t3a -a x -k "$KC3"
[ "$("$KC" get -s t3a -a x -k "$KC3")" = "abc" ] && ok "t3: abc\\n -> abc" || fail "t3: abc\\n"
printf 'a\nb\n' | "$KC" set -s t3b -a x -k "$KC3"
[ "$("$KC" get -s t3b -a x -k "$KC3")" = "$(printf 'a\nb')" ] && ok "t3: a\\nb\\n -> a\\nb" || fail "t3: a\\nb\\n"

# --- Test 4: duplicate / -U ---
KC4=$(mkkc 4); KEYCHAINS+=("$KC4")
printf 'v1' | "$KC" set -s t4 -a x -k "$KC4"
printf 'v2' | "$KC" set -s t4 -a x -k "$KC4" 2>/dev/null
expect_exit 45 $? "t4: duplicate without -U"
printf 'v2' | "$KC" set -s t4 -a x -U -k "$KC4"
expect_exit 0 $? "t4: set -U"
[ "$("$KC" get -s t4 -a x -k "$KC4")" = "v2" ] && ok "t4: -U updated value" || fail "t4: -U value"

# --- Test 5: delete ---
KC5=$(mkkc 5); KEYCHAINS+=("$KC5")
printf 'v' | "$KC" set -s t5 -a x -k "$KC5"
"$KC" delete -s t5 -a x -k "$KC5"
expect_exit 0 $? "t5: delete"
"$KC" get -s t5 -a x -k "$KC5" 2>/dev/null
expect_exit 44 $? "t5: get after delete"
"$KC" delete -s t5 -a x -k "$KC5" 2>/dev/null
expect_exit 44 $? "t5: delete missing"
# Partial filter deletes exactly one item, not all matches
printf 'v1' | "$KC" set -s t5multi -a a1 -k "$KC5"
printf 'v2' | "$KC" set -s t5multi -a a2 -k "$KC5"
"$KC" delete -s t5multi -k "$KC5"
expect_exit 0 $? "t5: delete by -s only"
N=$(security dump-keychain "$KC5" 2>/dev/null | grep -c '"svce"<blob>="t5multi"')
if [ "$N" = "1" ]; then ok "t5: exactly one of two items remains ($N)"; else fail "t5: expected 1 item left, found $N"; fi

# --- Test 6: ACLs ---
KC6=$(mkkc 6); KEYCHAINS+=("$KC6")
printf 'v' | "$KC" set -s t6def -a x -k "$KC6"
DUMP=$(security dump-keychain -a "$KC6" 2>/dev/null)
ITEM6=$(echo "$DUMP" | awk '/"svce"<blob>="t6def"/,/keychain:/')
echo "$ITEM6" | grep -q '/usr/bin/security' && ok "t6: default ACL trusts /usr/bin/security" || fail "t6: security in ACL"
echo "$ITEM6" | grep -q "$KC" && ok "t6: default ACL trusts kc" || fail "t6: kc in ACL"
printf 'v' | "$KC" set -s t6t -a x -T /usr/bin/true -k "$KC6"
ITEM6T=$(security dump-keychain -a "$KC6" 2>/dev/null | awk '/"svce"<blob>="t6t"/,/keychain:/')
echo "$ITEM6T" | grep -q '/usr/bin/true' && ok "t6: -T adds /usr/bin/true" || fail "t6: -T"
printf 'v' | "$KC" set -s t6a -a x -A -k "$KC6"
security add-generic-password -s t6ref -a x -w v -A "$KC6" >/dev/null
DUMP6=$(security dump-keychain -a "$KC6" 2>/dev/null)
ITEM6A=$(echo "$DUMP6" | awk '/"svce"<blob>="t6a"/,/keychain:/')
ITEM6R=$(echo "$DUMP6" | awk '/"svce"<blob>="t6ref"/,/keychain:/')
# Compare application lists of decrypt entries
appA=$(echo "$ITEM6A" | grep -A6 'decrypt derive' | grep 'applications')
appR=$(echo "$ITEM6R" | grep -A6 'decrypt derive' | grep 'applications')
if [ "$appA" = "$appR" ]; then ok "t6: -A matches security -A ($appA)"; else fail "t6: -A ($appA) vs security ($appR)"; fi

# --- Test 6b: -j (comment->icmt) and -D (kind->desc) attribute mapping ---
KC6B=$(mkkc 6b); KEYCHAINS+=("$KC6B")
printf 'v' | "$KC" set -s t6b -a x -j mycomment -D mykind -k "$KC6B"
FIND=$(security find-generic-password -s t6b -a x "$KC6B" 2>/dev/null)
echo "$FIND" | grep -q '"icmt"<blob>="mycomment"' && ok "t6b: -j -> icmt" || fail "t6b: icmt missing"
echo "$FIND" | grep -q '"desc"<blob>="mykind"' && ok "t6b: -D -> desc" || fail "t6b: desc missing"
# -U updates comment/kind too
printf 'v2' | "$KC" set -s t6b -a x -U -j c2 -D k2 -k "$KC6B"
FIND2=$(security find-generic-password -s t6b -a x "$KC6B" 2>/dev/null)
echo "$FIND2" | grep -q '"icmt"<blob>="c2"' && echo "$FIND2" | grep -q '"desc"<blob>="k2"' \
    && ok "t6b: -U updates icmt/desc" || fail "t6b: -U did not update icmt/desc"

# --- Test 6c: partial-filter get ---
printf 'vv' | "$KC" set -s t6c -a acct1 -k "$KC6B"
[ "$("$KC" get -a acct1 -k "$KC6B")" = "vv" ] && ok "t6c: get by -a only" || fail "t6c: get by -a only"
[ "$("$KC" get -s t6c -k "$KC6B")" = "vv" ] && ok "t6c: get by -s only" || fail "t6c: get by -s only"

# --- Test 7: usage / version ---
"$KC" >/dev/null 2>&1
expect_exit 64 $? "t7: no args"
"$KC" 2>&1 | grep -q 'Usage' && ok "t7: usage text" || fail "t7: usage text"
V=$("$KC" --version)
[ -n "$V" ] && ok "t7: --version ($V)" || fail "t7: --version"
[ "$("$KC" --help | tail -c1 | xxd -p | tr -d ' \n')" = "0a" ] && ok "t7: help ends with newline" || fail "t7: help missing trailing newline"

# --- Test 8: -u alias, -s requirement, $USER account default ---
KC8=$(mkkc 8); KEYCHAINS+=("$KC8")
printf 'v' | "$KC" set -s t8 -u name -k "$KC8"
expect_exit 0 $? "t8: set -u"
security find-generic-password -s t8 "$KC8" 2>/dev/null | grep -q '"acct"<blob>="name"' \
    && ok "t8: -u stored account name" || fail "t8: -u account"
[ "$("$KC" get -u name -k "$KC8")" = "v" ] && ok "t8: get -u" || fail "t8: get -u"
printf 'v' | "$KC" set -s t8def -k "$KC8"
expect_exit 0 $? "t8: set with no -a"
ME=$(id -un)
security find-generic-password -s t8def "$KC8" 2>/dev/null | grep -q "\"acct\"<blob>=\"$ME\"" \
    && ok "t8: account defaults to $USER ($ME)" || fail "t8: account default"
printf 'v' | "$KC" set -a x -k "$KC8" 2>/tmp/t8err
expect_exit 64 $? "t8: set without -s"
grep -q 'set requires -s' /tmp/t8err && ok "t8: stderr says set requires -s" || fail "t8: missing -s message"
"$KC" get -k "$KC8" 2>/dev/null
expect_exit 64 $? "t8: get with no -s/-a"

echo
if [ "$FAIL" -eq 0 ]; then echo "ALL TESTS PASSED"; else echo "SOME TESTS FAILED"; exit 1; fi
