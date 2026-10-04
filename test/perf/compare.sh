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
# The build files of each checkout are its own (build_config.rb,
# build_config.rb.lock, build.sh, ...); the measurement (this script,
# test/perf/perf.rb and the scenarios in test/soak/) comes from this checkout.
#
# Each build takes the third-party gems at the commits of the
# build_config.rb.lock committed in its checkout, so the gems differ only
# where the head changes the lock, and a pull request that moves a gem to
# another commit is measured with that commit, as it would be merged. A
# checkout that has no lock (one from before the lock was committed) takes the
# lock of the other side: the base the head's, the head the lock that the
# base build wrote. perf.rb reports the gems at different commits.
#
# The exit status is 1 when a scenario does 5% more work in head
# (PERF_FAIL_PERCENT), when a measurement fails (in the base, an unexpected
# response whose only other problems are ngx_mruby's "mrb_run failed" lines
# only marks the scenario n/a), or when no scenario was compared.

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
    # An empty RELEASE_GEM_LOCK makes test/build_release.sh take the lock
    # committed in the checkout it builds.
    base_lock=
    if [ ! -f "$BASE/build_config.rb.lock" ] && [ -f "$HEAD/build_config.rb.lock" ]; then
        base_lock="$HEAD/build_config.rb.lock"
    fi
    RELEASE_CC_OPT= RELEASE_GEM_LOCK="$base_lock" \
        sh "$ROOT/test/build_release.sh" "$BASE" "$ROOT/build_perf/base"
    head_lock=
    if [ ! -f "$HEAD/build_config.rb.lock" ]; then
        head_lock="$ROOT/build_perf/base/tree/build_config.rb.lock"
    fi
    RELEASE_CC_OPT= RELEASE_GEM_LOCK="$head_lock" \
        sh "$ROOT/test/build_release.sh" "$HEAD" "$ROOT/build_perf/head"
fi

exec ruby "$ROOT/test/perf/perf.rb" "$ROOT/build_perf/base" "$ROOT/build_perf/head"
