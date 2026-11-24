#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
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

# The tests of upstream's `make check` that run without a private mount namespace, with the
# programs of the normal-flags build in mayhem/build-test (built by build.sh). Each is one CTRF test:
#   test-collect          collect's ID bookkeeping and exit codes against expected outputs
#   test-json-writer      the JSON writer of udevadm against expected strings
#   test-scsi_id          get_file_options()/scsi_id main() with a fake disk: options, exit codes, messages
#   hwdb-test.sh          udevadm hwdb --update on unreadable/missing dirs and files
#   dmi-memory-id-test.sh dmi_memory_id -F on the dumps vs. their expected .txt output
#   rules-test.sh         udevadm verify on every shipped rules file
# Exit status 77 means skipped (automake convention), 0 passed, anything else failed.
BT="$SRC/mayhem/build-test"
for f in "$BT/test/test-collect" "$BT/test/test-json-writer" "$BT/test/test-scsi_id" "$BT/src/udev/udevadm" \
         "$BT/src/dmi_memory_id/dmi_memory_id"; do
  [ -x "$f" ] || { echo "missing $f: run mayhem/build.sh first" >&2; emit_ctrf eudev-make-check 0 1; exit 1; }
done

passed=0 failed=0 skipped=0
run_test() {
  local name="$1"; shift
  local log; log=$(mktemp)
  ( "$@" ) >"$log" 2>&1
  local rc=$?
  case $rc in
    0)  passed=$((passed + 1)); echo "PASS: $name" ;;
    77) skipped=$((skipped + 1)); echo "SKIP: $name" ;;
    *)  failed=$((failed + 1)); echo "FAIL: $name (exit $rc)"; tail -n 40 "$log" ;;
  esac
  rm -f "$log"
}

export UDEV_DEVICE_VERIFY_SYSFS=0
cd "$BT/test"
run_test test-collect ./test-collect
run_test test-json-writer ./test-json-writer
run_test test-scsi_id ./test-scsi_id
run_test hwdb-test.sh env TEST_UDEVADM="$BT/src/udev/udevadm" sh "$SRC/test/hwdb-test.sh"
run_test dmi-memory-id-test.sh env TEST_DMI_MEMORY_ID="$BT/src/dmi_memory_id/dmi_memory_id" \
  sh "$SRC/test/dmi-memory-id-test.sh"
run_test rules-test.sh env top_srcdir="$SRC" abs_top_builddir="$BT" generated_rules= \
  sh "$SRC/test/rules-test.sh"
cd "$SRC"
emit_ctrf eudev-make-check "$passed" "$failed" "$skipped"
