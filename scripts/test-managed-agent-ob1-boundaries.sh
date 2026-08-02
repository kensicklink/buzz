#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-managed-agent-ob1-boundaries.sh"

if [[ ! -x "$CHECK" ]]; then
  chmod +x "$CHECK"
fi

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/managed-agent-ob1-tests.XXXXXX")"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

write_snapshot() {
  local name="$1"
  shift
  local path="$tmpdir/$name.snapshot"
  printf '%s\n' "$@" > "$path"
  printf '%s\n' "$path"
}

expect_pass() {
  local name="$1"
  local runtime="$2"
  local pid="$3"
  local snapshot="$4"
  local required="$5"
  local forbidden="${6:-}"
  local output
  output="$("$CHECK" --runtime "$runtime" --pid "$pid" --snapshot "$snapshot")"
  if ! grep -q "PASS runtime=$runtime root_pid=$pid" <<<"$output"; then
    echo "FAIL $name: expected pass"
    echo "$output"
    exit 1
  fi
  if ! grep -q "$required" <<<"$output"; then
    echo "FAIL $name: missing evidence pattern $required"
    echo "$output"
    exit 1
  fi
  if [[ -n "$forbidden" ]] && grep -q "$forbidden" <<<"$output"; then
    echo "FAIL $name: leaked forbidden evidence pattern $forbidden"
    echo "$output"
    exit 1
  fi
  echo "ok $name"
}

expect_fail() {
  local name="$1"
  local runtime="$2"
  local pid="$3"
  local snapshot="$4"
  local reason="$5"
  local output
  if output="$("$CHECK" --runtime "$runtime" --pid "$pid" --snapshot "$snapshot" 2>&1)"; then
    echo "FAIL $name: expected failure"
    echo "$output"
    exit 1
  fi
  if ! grep -q "reason=$reason" <<<"$output"; then
    echo "FAIL $name: missing failure reason $reason"
    echo "$output"
    exit 1
  fi
  echo "ok $name"
}

cursor_positive="$(write_snapshot cursor-positive \
  "100 1 /Applications/Cursor.app/Contents/Resources/app/bin/cursor-agent acp" \
  "101 100 node /Applications/Cursor.app/worker.js" \
  "102 101 open-brain-broker --mode read-only --scope metadata --api-key fake-secret-value")"
expect_pass "cursor allows read-only broker" "cursor" "100" "$cursor_positive" "allowed_read_only_broker pid=102" "fake-secret-value"

cursor_negative="$(write_snapshot cursor-negative \
  "110 1 cursor-agent acp" \
  "111 110 open-brain-writer --mode write")"
expect_fail "cursor blocks writer" "cursor" "110" "$cursor_negative" "open_brain_writer"

grok_positive="$(write_snapshot grok-positive \
  "200 1 /usr/local/bin/grok agent stdio" \
  "201 200 grok-worker --stdio")"
expect_pass "grok keeps stdio entrypoint" "grok" "200" "$grok_positive" "root pid=200"

grok_staging_negative="$(write_snapshot grok-staging-negative \
  "210 1 grok agent stdio" \
  "211 210 open-brain-staging-broker --stdio")"
expect_fail "grok blocks staging broker" "grok" "210" "$grok_staging_negative" "open_brain_staging_broker"

grok_approval_negative="$(write_snapshot grok-approval-negative \
  "220 1 grok agent --always-approve stdio")"
expect_fail "grok blocks approval bypass" "grok" "220" "$grok_approval_negative" "approval_bypass_arg"

echo "managed-agent OB1 boundary synthetic tests passed"
