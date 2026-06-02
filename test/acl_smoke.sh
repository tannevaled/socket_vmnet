#!/bin/sh
# Offline integration smoke-test for the c-fw ACL front-end wired into the
# daemon. It exercises the REAL daemon code path (main.c load_acl_file ->
# libfw/c-fw acl_load_hcl via libhcl/c-hcl for .hcl, acl_load via json.c for
# .json) without needing root or vmnet: the daemon only WARNs when not root and
# loads the ACL *before* it touches vmnet.framework, so a good ACL is reported
# as loaded and the run proceeds to the (expected) vmnet failure, while a bad
# ACL fails closed and never reaches vmnet.
#
# The full datapath (frames actually flowing through a VM) still requires root
# + a Lima guest -- see ACL.md ("Testing the ACL integration") for that runbook.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="$ROOT/socket_vmnet"
if [ ! -x "$BIN" ]; then
  echo "SKIP: $BIN not built (run 'make socket_vmnet' first)"
  exit 0
fi

TMPOUT=$(mktemp /tmp/sv_smoke.XXXXXX)
SOCK=$(mktemp -u /tmp/sv_smoke.XXXXXX.sock)
trap 'rm -f "$TMPOUT" "$SOCK"' EXIT

# Run the daemon against an ACL file with a wall-clock watchdog (it normally
# exits on its own when vmnet_start_interface fails without root).
run() {
  rm -f "$SOCK"
  "$BIN" --acl "$1" "$SOCK" >"$TMPOUT" 2>&1 &
  pid=$!
  i=0
  while [ "$i" -lt 10 ]; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.5
    i=$((i + 1))
  done
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  rm -f "$SOCK"
  cat "$TMPOUT"
}

fail=0
expect() { # desc haystack needle
  case "$2" in
  *"$3"*) echo "ok:   $1" ;;
  *) echo "FAIL: $1 (expected to find: $3)"; fail=1 ;;
  esac
}
refute() { # desc haystack needle
  case "$2" in
  *"$3"*) echo "FAIL: $1 (unexpectedly found: $3)"; fail=1 ;;
  *) echo "ok:   $1" ;;
  esac
}

out=$(run "$ROOT/test/acl_ok.hcl")
expect "good .hcl loads rules"     "$out" "acl: loaded 5 rule(s)"
expect "good .hcl reaches vmnet"   "$out" "Initializing vmnet.framework"

out=$(run "$ROOT/test/acl_ok.json")
expect "good .json loads rules"    "$out" "acl: loaded 3 rule(s)"
expect "good .json reaches vmnet"  "$out" "Initializing vmnet.framework"

out=$(run "$ROOT/test/acl_bad.hcl")
expect "bad .hcl reports parse err" "$out" "failed to compile"
refute "bad .hcl fails closed"      "$out" "Initializing vmnet.framework"

if [ "$fail" -eq 0 ]; then
  echo
  echo "ACL load smoke passed."
  exit 0
fi
echo
echo "ACL load smoke FAILED."
exit 1
