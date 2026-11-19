#!/usr/bin/env bash
#
# mayhem/test.sh — upstream's meson test suite plus golden-output tests of ping, tracepath, clockdiff
# and arping (all built by build.sh). One CTRF report counts both.
#
# 1) Upstream's suite (test/*/meson.build, perl Test::Command) on upstream's meson build: the -V
#    checks, the option-parsing failures and the loopback pings (ping uses an unprivileged ICMP
#    socket, which the image allows when net.ipv4.ping_group_range covers the user). Excluded by name:
#    `json` (test/ping/test_json.py downloads a JSON schema from opensuse.org; the image is offline),
#    and — only when this environment has no ICMP socket for the user (probed below) — the tests
#    that ping loopback; they are counted as skipped.
# 2) Golden-output tests: each tool's real main() runs
#    on the mock network of mayhem/netshim.c (deterministic: virtual clock, fixed pid), fed a canned
# conversation from mayhem/tests/<tool>-<case>.in; its stdout+stderr and exit status must equal
# mayhem/tests/<tool>-<case>.out exactly — replies, RTTs, ICMP error decoding, IP option and NI
# reply printing, traceroute hops, clock deltas, ARP replies and the summary statistics.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

BIN="$SRC/builddir/mayhem/test"
TESTS="$SRC/mayhem/tests"
MESON_DIR="$SRC/builddir/mayhem/meson"
passed=0 failed=0 skipped=0

# ---- 1) upstream's meson test suite ----
if [ ! -f "$MESON_DIR/build.ninja" ] || ! command -v meson >/dev/null; then
  echo "FAIL meson: $MESON_DIR not configured or meson missing (build.sh builds it)"
  failed=$((failed + 1))
else
  mapfile -t all < <(meson test -C "$MESON_DIR" --list 2>/dev/null | sed 's/^[^:]*:[^ ]* \/ //; s/^[^:]*:\([^ ]\)/\1/')
  # Does this environment give the user an ICMP socket (ping's unprivileged path)?
  if perl -MSocket -e 'socket(my $s, PF_INET, SOCK_DGRAM, getprotobyname("icmp")) or exit 1'; then
    icmp=1
  else
    icmp=0
    echo "NOTE no ICMP socket for uid $(id -u) here (net.ipv4.ping_group_range): loopback ping tests skipped"
  fi
  run=() excluded=()
  for t in "${all[@]}"; do
    case "$t" in
      json) excluded+=("$t"); continue ;;
    esac
    if [ "$icmp" = 0 ]; then
      case "$t" in
        ping-0[12]-*.t|*127.0.0.1*|*localhost*|*__1*)
          # option-parsing failures exit before any socket is opened: keep them
          case "$t" in *-c1.1*|*nonexisting*|*-w0.1*|*-w0,1*) ;; *) excluded+=("$t"); continue ;; esac ;;
      esac
    fi
    run+=("$t")
  done
  if [ ${#run[@]} -eq 0 ]; then
    echo "FAIL meson: no tests listed by meson test --list"
    failed=$((failed + 1))
  else
    rm -f "$MESON_DIR/meson-logs/testlog.json"
    meson test -C "$MESON_DIR" --no-rebuild --print-errorlogs "${run[@]}" || true
    if [ ! -f "$MESON_DIR/meson-logs/testlog.json" ]; then
      echo "FAIL meson: no testlog.json"
      failed=$((failed + 1))
    else
      read -r mp mf ms < <(python3 -I -c '
import json, sys
p = f = s = 0
for line in open(sys.argv[1]):
    r = json.loads(line)["result"]
    if r in ("OK", "EXPECTEDFAIL"): p += 1
    elif r == "SKIP": s += 1
    else: f += 1
print(p, f, s)' "$MESON_DIR/meson-logs/testlog.json")
      echo "meson test: passed=$mp failed=$mf skipped=$ms excluded=${#excluded[@]} (${excluded[*]})"
      passed=$((passed + mp)); failed=$((failed + mf)); skipped=$((skipped + ms + ${#excluded[@]}))
    fi
  fi
fi

# ---- 2) golden-output tests on the mock network ----
shopt -s nullglob
cases=("$TESTS"/*.in)
if [ ${#cases[@]} -eq 0 ]; then
  echo "no test cases in $TESTS" >&2
  emit_ctrf meson-test+golden-output "$passed" $((failed + 1)) "$skipped"
  exit 1
fi
for in in "${cases[@]}"; do
  name=$(basename "$in" .in)
  tool=${name%%-*}
  [ "$tool" = ping ] && tool=ping_args
  exp="$TESTS/$name.out"
  if [ ! -x "$BIN/$tool" ]; then
    echo "FAIL $name: $BIN/$tool missing (build.sh did not build it)"
    failed=$((failed + 1)); continue
  fi
  if [ ! -f "$exp" ]; then
    echo "FAIL $name: no expected output $exp"
    failed=$((failed + 1)); continue
  fi
  got=$( (cd "$TESTS" && timeout 20 "$BIN/$tool" "$name.in" 2>&1; echo "exit=$?") )
  if diff -u "$exp" <(printf '%s\n' "$got") > /tmp/iputils-test-$$.diff; then
    echo "PASS $name"; passed=$((passed + 1))
  else
    echo "FAIL $name"; cat /tmp/iputils-test-$$.diff; failed=$((failed + 1))
  fi
  rm -f /tmp/iputils-test-$$.diff
done
emit_ctrf meson-test+golden-output "$passed" "$failed" "$skipped"
