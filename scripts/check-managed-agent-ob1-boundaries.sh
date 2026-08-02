#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: check-managed-agent-ob1-boundaries.sh --runtime cursor|grok --pid PID [--snapshot FILE] [--evidence-out FILE]

Read-only process-tree boundary check. The checker inspects only PID, PPID, and
command text. Tests should always pass --snapshot so no current processes are read.

Snapshot format: one process per line as "PID PPID COMMAND...".
USAGE
}

runtime=""
root_pid=""
snapshot=""
evidence_out=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime)
      runtime="${2:-}"
      shift 2
      ;;
    --pid)
      root_pid="${2:-}"
      shift 2
      ;;
    --snapshot)
      snapshot="${2:-}"
      shift 2
      ;;
    --evidence-out)
      evidence_out="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 64
      ;;
  esac
done

if [[ "$runtime" != "cursor" && "$runtime" != "grok" ]]; then
  echo "FAIL reason=invalid_runtime expected=cursor|grok" >&2
  exit 64
fi

if [[ ! "$root_pid" =~ ^[0-9]+$ ]]; then
  echo "FAIL runtime=$runtime reason=invalid_pid" >&2
  exit 64
fi

input_file=""
cleanup_input=""
if [[ -n "$snapshot" ]]; then
  if [[ ! -r "$snapshot" ]]; then
    echo "FAIL runtime=$runtime root_pid=$root_pid reason=snapshot_unreadable" >&2
    exit 66
  fi
  input_file="$snapshot"
else
  input_file="$(mktemp "${TMPDIR:-/tmp}/managed-agent-ob1-ps.XXXXXX")"
  cleanup_input="$input_file"
  # Read-only live mode for steward receipts. This inspects PID, PPID, and
  # command text only. Worker tests must use --snapshot instead.
  ps -axo pid=,ppid=,command= > "$input_file"
fi

output_file="$(mktemp "${TMPDIR:-/tmp}/managed-agent-ob1-evidence.XXXXXX")"
cleanup() {
  rm -f "$output_file"
  if [[ -n "$cleanup_input" ]]; then
    rm -f "$cleanup_input"
  fi
}
trap cleanup EXIT

set +e
awk -v root="$root_pid" -v runtime="$runtime" '
function trim(s) {
  sub(/^[[:space:]]+/, "", s)
  sub(/[[:space:]]+$/, "", s)
  return s
}

function redact(cmd, parts, n, i, part, lower, out, sep) {
  gsub(/[[:space:]]+/, " ", cmd)
  cmd = trim(cmd)
  n = split(cmd, parts, " ")
  out = ""
  sep = ""
  for (i = 1; i <= n; i++) {
    part = parts[i]
    lower = tolower(part)
    if (part ~ /^sk-[A-Za-z0-9_-]+$/) {
      part = "sk-...REDACTED"
    }
    if (lower ~ /(key|token|secret|password|credential)=/) {
      sub(/=.*/, "=REDACTED", part)
    }
    if (lower ~ /^--.*(key|token|secret|password|credential)=/) {
      sub(/=.*/, "=REDACTED", part)
    } else if (lower ~ /^--.*(key|token|secret|password|credential)$/ && i < n) {
      out = out sep part
      sep = " "
      i++
      part = "REDACTED"
    }
    out = out sep part
    sep = " "
  }
  return out
}

function command_after_two_fields(line) {
  sub(/^[[:space:]]+/, "", line)
  sub(/^[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]*/, "", line)
  return trim(line)
}

function runtime_matches(cmd, lower) {
  lower = tolower(cmd)
  if (runtime == "cursor") {
    return lower ~ /(^|[\/[:space:]])cursor-agent([[:space:]]|$)/ && lower ~ /(^|[[:space:]])acp([[:space:]]|$)/
  }
  if (runtime == "grok") {
    return lower ~ /(^|[\/[:space:]])grok([[:space:]]|$)/ && lower ~ /(^|[[:space:]])agent([[:space:]]|$)/ && lower ~ /(^|[[:space:]])stdio([[:space:]]|$)/
  }
  return 0
}

function approval_bypass(cmd, lower) {
  lower = tolower(cmd)
  return lower ~ /--always-approve|--auto-approve|--dangerously-skip|approval[-_ ]?bypass/
}

function ob_runtime_token(lower) {
  return lower ~ /(open[-_ ]?brain|openbrain|ob1)/
}

function ob_broker_token(lower) {
  return lower ~ /broker/
}

function ob_read_only_token(lower) {
  return lower ~ /(read[-_ ]?only|readonly|--read-only|--mode[= ]read-only)/
}

function classify_ob1(cmd, lower) {
  lower = tolower(cmd)
  if (ob_broker_token(lower) && lower ~ /staging/) {
    return "open_brain_staging_broker"
  }
  if (!ob_runtime_token(lower)) {
    return ""
  }
  if (lower ~ /(writer|--write|--mode[= ]write|[[:space:]]write([[:space:]]|$)|write-enabled|mutation)/) {
    return "open_brain_writer"
  }
  if (ob_broker_token(lower)) {
    if (ob_read_only_token(lower)) {
      return "allowed_read_only_broker"
    }
    return "open_brain_broker_not_read_only"
  }
  return ""
}

function fail(reason, pid, kind) {
  printf "FAIL runtime=%s root_pid=%s reason=%s\n", runtime, root, reason
  if (pid != "") {
    printf "evidence pid=%s ppid=%s kind=%s cmd=%s\n", pid, ppid[pid], kind, redact(cmd[pid])
  } else if (root in cmd) {
    printf "root pid=%s ppid=%s cmd=%s\n", root, ppid[root], redact(cmd[root])
  }
  exit 1
}

BEGIN {
  malformed = 0
  duplicate = ""
  count = 0
}

NF == 0 { next }
tolower($1) == "pid" { next }

{
  line = $0
  p = $1
  pp = $2
  if (p !~ /^[0-9]+$/ || pp !~ /^[0-9]+$/ || NF < 3) {
    malformed = 1
    next
  }
  if (p in cmd) {
    duplicate = p
    next
  }
  ppid[p] = pp
  cmd[p] = command_after_two_fields(line)
  count++
}

END {
  if (malformed) {
    fail("malformed_snapshot", "", "")
  }
  if (duplicate != "") {
    fail("duplicate_pid", duplicate, "duplicate_pid")
  }
  if (!(root in cmd)) {
    fail("root_pid_not_found", "", "")
  }

  selected[root] = 1
  for (i = 0; i <= count; i++) {
    changed = 0
    for (pid in cmd) {
      if (!((pid in selected) && selected[pid]) && ((ppid[pid] in selected) && selected[ppid[pid]])) {
        selected[pid] = 1
        changed = 1
      }
    }
    if (!changed) {
      break
    }
  }

  tree_count = 0
  allowed_count = 0
  for (pid in selected) {
    if (selected[pid]) {
      tree_count++
    }
  }
  if (tree_count == 0) {
    fail("empty_runtime_tree", "", "")
  }
  if (!runtime_matches(cmd[root])) {
    fail("runtime_root_mismatch", root, "runtime_root")
  }
  if (runtime == "grok" && approval_bypass(cmd[root])) {
    fail("approval_bypass_arg", root, "approval_bypass_arg")
  }

  for (pid in selected) {
    if (!selected[pid]) {
      continue
    }
    kind = classify_ob1(cmd[pid])
    if (kind == "allowed_read_only_broker") {
      allowed[++allowed_count] = pid
    } else if (kind != "") {
      fail(kind, pid, kind)
    }
  }

  printf "PASS runtime=%s root_pid=%s tree_pids=%d\n", runtime, root, tree_count
  printf "root pid=%s ppid=%s cmd=%s\n", root, ppid[root], redact(cmd[root])
  for (i = 1; i <= allowed_count; i++) {
    pid = allowed[i]
    printf "allowed_read_only_broker pid=%s ppid=%s cmd=%s\n", pid, ppid[pid], redact(cmd[pid])
  }
}
' "$input_file" > "$output_file"
status=$?
set -e

cat "$output_file"
if [[ -n "$evidence_out" ]]; then
  cp "$output_file" "$evidence_out"
fi

exit "$status"
