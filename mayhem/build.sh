#!/usr/bin/env bash
#
# mayhem/build.sh — builds eudev twice, out of tree under mayhem/ (both dirs gitignored by mayhem/.gitignore):
#   mayhem/build-fuzz  the project with $SANITIZER_FLAGS + SanCov + $DEBUG_FLAGS, then the libFuzzer
#                      harnesses and their -standalone reproducers, linked against its static libs
#   mayhem/build-test  the project with its normal flags + the check programs, which mayhem/test.sh runs
# Re-runnable (configure only when there is no Makefile yet) and offline (apt packages only).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:?STANDALONE_FUZZ_MAIN must be set (the base image provides it)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# configure is generated (gitignored); do NOT run ./autogen.sh, which also builds the man pages (xsltproc).
[ -x configure ] || autoreconf -f -i -s

CONF_ARGS=(--disable-manpages --disable-selinux --disable-kmod --disable-blkid
           --enable-static --disable-shared --prefix=/usr --sysconfdir=/etc)

# 1) Sanitized + SanCov-instrumented project (the fuzzed code), DWARF 3.
FUZZ_CFLAGS="-O1 $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
mkdir -p mayhem/build-fuzz
( cd mayhem/build-fuzz
  [ -f Makefile ] || ../../configure "${CONF_ARGS[@]}" CC="$CC" CFLAGS="$FUZZ_CFLAGS"
  make -j"$MAYHEM_JOBS" )

B="$SRC/mayhem/build-fuzz"
OUT="$SRC/mayhem/bin"; mkdir -p "$OUT"
LIBS=("$B/src/udev/.libs/libudev-core.a" "$B/src/libudev/.libs/libudev-private.a"
      "$B/src/shared/.libs/libudev_shared.a")
CPPFLAGS=(-include "$B/config.h" -I "$B" -isystem "$SRC/src/include/glibc"
          -I "$SRC/src/shared" -I "$SRC/src/libudev" -I "$SRC/src/udev" -I "$B/src/udev"
          -DPROJECT_SUBDIR=\"mayhem\" -DPROJECT_TOP_SRCDIR=\"$SRC\"
          -DUDEV_VERSION=\"$(sed -n 's/^UDEV_VERSION = //p' "$B/src/udev/Makefile")\"
          -DVERSION=\"$(sed -n 's/^VERSION = //p' "$B/src/udev/Makefile")\")

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

# 2) Each harness twice: the libFuzzer binary and the run-once reproducer.
for h in fuzz_rules_verify fuzz_hwdb_bin fuzz_hwdb_update fuzz_dmi_memory_id; do
  $CC -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link "${CPPFLAGS[@]}" \
      -c "$SRC/mayhem/$h.c" -o "$B/$h.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/$h.o" "${LIBS[@]}" "$B/lsan_off.o" \
      -lm -o "$OUT/$h"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link "$B/$h.o" "$B/standalone_main.o" \
      "${LIBS[@]}" "$B/lsan_off.o" -lm -o "$OUT/$h-standalone"
done

# The monitor harness wraps recvmsg() (see the harness) to supply the netlink address and root credentials.
$CC -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link "${CPPFLAGS[@]}" \
    -c "$SRC/mayhem/fuzz_monitor_receive.c" -o "$B/fuzz_monitor_receive.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -Wl,--wrap=recvmsg "$B/fuzz_monitor_receive.o" \
    "${LIBS[@]}" "$B/lsan_off.o" -lm -o "$OUT/fuzz_monitor_receive"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -Wl,--wrap=recvmsg "$B/fuzz_monitor_receive.o" \
    "$B/standalone_main.o" "${LIBS[@]}" "$B/lsan_off.o" -lm -o "$OUT/fuzz_monitor_receive-standalone"

# scsi_id's config parser: the harness includes src/scsi_id/scsi_id.c itself, so it links the tool's
# other object (scsi_serial) but not the tool's own scsi_id object.
SCSI_OBJS=()
for o in "$B"/src/scsi_id/*.o; do case "$o" in *scsi_id-scsi_id.o|*/scsi_id.o) ;; *) SCSI_OBJS+=("$o");; esac; done
$CC -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link "${CPPFLAGS[@]}" -I "$SRC/src/scsi_id" \
    -c "$SRC/mayhem/fuzz_scsi_id_config.c" -o "$B/fuzz_scsi_id_config.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/fuzz_scsi_id_config.o" "${SCSI_OBJS[@]}" \
    "${LIBS[@]}" "$B/lsan_off.o" -lm -o "$OUT/fuzz_scsi_id_config"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link "$B/fuzz_scsi_id_config.o" "$B/standalone_main.o" \
    "${SCSI_OBJS[@]}" "${LIBS[@]}" "$B/lsan_off.o" -lm -o "$OUT/fuzz_scsi_id_config-standalone"
rm -f "$OUT/scsi_id"

# 3) The test build: normal flags, plus the check programs (built, not run: test.sh runs them).
mkdir -p mayhem/build-test
( cd mayhem/build-test
  [ -f Makefile ] || env -u CFLAGS -u LDFLAGS ../../configure "${CONF_ARGS[@]}" CC="$CC" \
      CFLAGS="-O2 -g $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS"
  make -j"$MAYHEM_JOBS"
  make -j"$MAYHEM_JOBS" -C test test-collect test-json-writer test-scsi_id test/sys )
