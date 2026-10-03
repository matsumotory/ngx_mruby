#!/bin/sh
#
# Build one checkout for the performance comparison and measure its
# instructions per request with callgrind. Needs valgrind with
# callgrind_control and vgdb, which work on Linux (on macOS, run it in a
# Linux container). See docs/test/README.md, "Performance comparison with
# callgrind".
#
#   sh test/perf/run.sh [SOURCE_DIR [NAME]]             # build, then measure
#   ONLY_RUN=1 sh test/perf/run.sh [SOURCE_DIR [NAME]]  # measure the existing build
#
# SOURCE_DIR is the checkout to build (default: this one); the build goes to
# build_perf/NAME (default: head). To compare two checkouts, use
# test/perf/compare.sh.
#
# The perf build is test/build_release.sh with nothing added: -O2 -g,
# neither MRB_GC_STRESS nor --with-debug, as for the soak build, but also
# without the soak build's NGX_MRUBY_DEBUG_STATS and MRB_USE_MALLOC_TRIM,
# which change the code under measurement. NGX_MRUBY_CFLAGS from the
# environment still reaches mruby, as with test.sh.

set -e

cd "$(dirname "$0")/../.."
ROOT=$(pwd)
SRC=${1:-$ROOT}
NAME=${2:-head}

# The check of the profile parser (no build, no valgrind; a few milliseconds).
ruby "$ROOT/test/perf/perf.rb" --self-test

if [ -z "$ONLY_RUN" ]; then
    RELEASE_CC_OPT= RELEASE_GEM_LOCK= \
        sh "$ROOT/test/build_release.sh" "$SRC" "$ROOT/build_perf/$NAME"
fi

exec ruby "$ROOT/test/perf/perf.rb" "$ROOT/build_perf/$NAME"
