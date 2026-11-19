#!/usr/bin/env bash
#
# mayhem/build.sh — build the iputils fuzz targets and the oracle binaries.
#
# The fuzz targets and the golden-output drivers are compiled directly with the config.h meson would
# generate (mayhem/config.h: no libcap, no IDN, no gettext) and the version header from meson.build;
# upstream's own meson build (same options) is built too, for upstream's test suite (meson test).
#
# Each tool's real main() is linked with mayhem/fuzz_main.c (reads one input file, picks the command
# line, then calls the tool) and mayhem/netshim.c, which mocks the libc network/time calls named in
# mayhem/netshim.syms through -Wl,--wrap so the tool receives its packets from the input.
#
#   builddir/mayhem/<target>_fuzz   AFL-instrumented, ASan+UBSan (halting), DWARF 3 — the Mayhem targets
#   builddir/mayhem/test/<tool>     same drivers, normal flags, no sanitizers — the golden-output tests
#   builddir/mayhem/meson/          upstream's meson build, normal flags — upstream's meson test suite
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
# AFL instrumentation (the targets are file-input tools that exit(); Mayhem runs them as afl: true).
: "${AFL_CC_WRAPPER:=afl-clang-fast}"
export AFL_CC="$CC" AFL_QUIET=1

cd "$SRC"
OUT="$SRC/builddir/mayhem"	# under /builddir, which upstream .gitignore already ignores
mkdir -p "$OUT/obj-fuzz" "$OUT/obj-test" "$OUT/test"

# The header meson's vcs_tag() would write; version from meson.build.
version=$(sed -n "s/^[[:space:]]*version : '\([^']*\)'.*/\1/p" meson.build | head -1)
sed "s/@VCS_TAG@/${version:-unknown}/" git-version.h.meson > "$OUT/git-version.h.tmp"
cmp -s "$OUT/git-version.h.tmp" "$OUT/git-version.h" 2>/dev/null || mv "$OUT/git-version.h.tmp" "$OUT/git-version.h"
rm -f "$OUT/git-version.h.tmp"

COMMON="-std=c11 -include $SRC/mayhem/config.h -include $OUT/git-version.h -I$SRC -I$SRC/ping -I$SRC/mayhem"
WRAP=$(tr -s ' \n' '\n' < "$SRC/mayhem/netshim.syms" | sed '/^$/d; s/^/-Wl,--wrap=/' | tr '\n' ' ')

PING_SRCS="ping/ping.c ping/ping_common.c ping/ping6_common.c ping/ping_json.c ping/ping_output.c ping/node_info.c"
LIB_SRCS="iputils_common.c md5.c"

# compile <cc> <flags> <objdir> <src> [extra]: object path on stdout
compile() {
	local cc="$1" flags="$2" dir="$3" src="$4" extra="${5:-}"
	local obj="$dir/$(echo "$src" | tr '/' '_' | sed 's/\.c$//')${6:-}.o"
	# shellcheck disable=SC2086
	$cc $flags $COMMON $extra -c "$SRC/$src" -o "$obj"
	echo "$obj"
}

# build_set <cc> <compile flags> <objdir> <out-suffix-dir> <name-suffix>
build_set() {
	local cc="$1" flags="$2" dir="$3" outdir="$4" sfx="$5"
	local lib=() ping=() tp cdo arp shim lsan=()
	for s in $LIB_SRCS; do lib+=("$(compile "$cc" "$flags" "$dir" "$s")"); done
	for s in $PING_SRCS; do
		if [ "$s" = ping/ping.c ]; then
			ping+=("$(compile "$cc" "$flags" "$dir" "$s" "-Dmain=tool_main")")
		else
			ping+=("$(compile "$cc" "$flags" "$dir" "$s")")
		fi
	done
	tp=$(compile "$cc" "$flags" "$dir" tracepath.c "-Dmain=tool_main")
	cdo=$(compile "$cc" "$flags" "$dir" clockdiff.c "-Dmain=tool_main")
	arp=$(compile "$cc" "$flags" "$dir" arping.c "-Dmain=tool_main")
	shim=$(compile "$cc" "$flags" "$dir" mayhem/netshim.c)
	if [ -n "$SANITIZER_FLAGS" ] && [ "$dir" = "$OUT/obj-fuzz" ]; then
		lsan=("$(compile "$cc" "$flags" "$dir" mayhem/lsan_off.c)")
	fi
	local t def objs
	for t in ping4 ping6 ping_args tracepath clockdiff arping; do
		def=$(echo "TOOL_$t" | tr 'a-z' 'A-Z')
		local drv
		drv=$(compile "$cc" "$flags" "$dir" mayhem/fuzz_main.c "-D$def" "_$t")
		case $t in
			ping*) objs=("${ping[@]}") ;;
			tracepath) objs=("$tp") ;;
			clockdiff) objs=("$cdo") ;;
			arping) objs=("$arp") ;;
		esac
		# shellcheck disable=SC2086
		$cc $flags $WRAP "$drv" "${objs[@]}" "${lib[@]}" "$shim" ${lsan[@]+"${lsan[@]}"} \
			-lm -lresolv -o "$outdir/$t$sfx"
	done
}

# 1) Fuzz targets: the whole project instrumented (AFL edges + ASan/UBSan), DWARF 3.
build_set "$AFL_CC_WRAPPER" "-O1 $SANITIZER_FLAGS $DEBUG_FLAGS" "$OUT/obj-fuzz" "$OUT" "_fuzz"

# 2) Oracle build: same drivers with the project's normal flags (meson's default buildtype is debug).
build_set "$CC" "-O0 -g $COVERAGE_FLAGS" "$OUT/obj-test" "$OUT/test" ""

# 3) Upstream's own build, normal flags (meson's default debug buildtype), for its test suite.
#    Features off to match mayhem/config.h (no libcap/libidn2/gettext in the image), no man pages.
MESON_OPTS=(-DUSE_CAP=false -DUSE_IDN=false -DUSE_GETTEXT=false -DBUILD_MANS=false -DBUILD_HTML_MANS=false)
MESON_OPTS+=("-Dc_args=$COVERAGE_FLAGS" "-Dc_link_args=$COVERAGE_FLAGS")
if [ -f "$OUT/meson/build.ninja" ]; then
	meson setup --reconfigure "$OUT/meson" "${MESON_OPTS[@]}"
else
	meson setup "$OUT/meson" "${MESON_OPTS[@]}"
fi
ninja -C "$OUT/meson" -j "$MAYHEM_JOBS"

ls -l "$OUT"/*_fuzz "$OUT"/test/ "$OUT"/meson/ping/ping "$OUT"/meson/tracepath "$OUT"/meson/arping "$OUT"/meson/clockdiff
