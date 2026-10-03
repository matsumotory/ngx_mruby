#!/bin/sh
#
# Compare the instructions per request of two checkouts, for example the base
# of a pull request and its head. Linux only, with valgrind. See
# docs/test/README.md, "Performance comparison with callgrind".
#
#   sh test/perf/compare.sh BASE_DIR [HEAD_DIR]             # build both, then measure and compare
#   ONLY_RUN=1 sh test/perf/compare.sh BASE_DIR [HEAD_DIR]  # measure and compare the existing builds
#
# BASE_DIR and HEAD_DIR (default: this checkout) are source checkouts, for
# example one made with
#
#   git archive --prefix=build_perf/base-src/ origin/next | tar -x
#
# BASE_DIR is built into build_perf/base and HEAD_DIR into build_perf/head,
# both with test/build_release.sh as test/perf/run.sh builds one checkout.
# The head build takes the gem lock of the base build (RELEASE_GEM_LOCK), so
# both build the third-party gems at the same commits. The build files of
# each checkout are its own (build_config.rb, build.sh, ...); the measurement
# (this script, test/perf/perf.rb and the scenarios in test/soak/) comes from
# this checkout.
#
# The exit status is 1 when a scenario does 5% more work in head
# (PERF_FAIL_PERCENT), when a measurement fails (in the base, an unexpected
# response with no other problem only marks the scenario n/a), or when no
# scenario was compared.

set -e

cd "$(dirname "$0")/../.."
ROOT=$(pwd)

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "usage: sh test/perf/compare.sh BASE_DIR [HEAD_DIR]" >&2
    exit 2
fi
BASE=$1
HEAD=${2:-$ROOT}

# The check of the profile parser (no build, no valgrind; a few milliseconds).
ruby "$ROOT/test/perf/perf.rb" --self-test

if [ -z "$ONLY_RUN" ]; then
    RELEASE_CC_OPT= RELEASE_GEM_LOCK= \
        sh "$ROOT/test/build_release.sh" "$BASE" "$ROOT/build_perf/base"
    RELEASE_CC_OPT= RELEASE_GEM_LOCK="$ROOT/build_perf/base/tree/build_config.rb.lock" \
        sh "$ROOT/test/build_release.sh" "$HEAD" "$ROOT/build_perf/head"
fi

exec ruby "$ROOT/test/perf/perf.rb" "$ROOT/build_perf/base" "$ROOT/build_perf/head"
