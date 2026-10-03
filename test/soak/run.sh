#!/bin/sh
#
# Build ngx_mruby for the memory soak test and run it. Linux only: the driver
# reads /proc. See docs/test/README.md, "Soak test for memory".
#
#   sh test/soak/run.sh              # build (incremental after the first run), then run
#   ONLY_RUN=1 sh test/soak/run.sh   # run against the existing build
#
# The soak build is test/build_release.sh in build_soak/ with two additions:
# it defines NGX_MRUBY_DEBUG_STATS (which adds the Nginx::Debug class), and
# mruby is built with MRB_USE_MALLOC_TRIM. Like every build of
# test/build_release.sh, it compiles nginx and ngx_mruby with -O2 -g and has
# neither MRB_GC_STRESS nor --with-debug, so that the memory use of the
# worker is close to that of a production build. With MRB_USE_MALLOC_TRIM,
# mrb_full_gc() calls malloc_trim(0), so the full GC that Nginx::Debug.gc
# runs before each sample also returns the free pages of the C heap, and
# VmRSS follows the memory in use instead of where the allocator happened to
# leave free memory. Without a call to GC.start or Nginx::Debug.gc, mruby
# runs a full GC only in rare cases (too many objects in one incremental GC,
# or a failed allocation).
#
# Layout (see test/build_release.sh for the build):
#   build_soak/tree          copy of the sources; the nginx source is in build_soak/tree/build
#   build_soak/nginx         nginx installed by `make install`
#   build_soak/nginx/soak    runtime prefix of the soak test (conf/, logs/)
#   build_soak/build_stamp   the untracked inputs of the last build

set -e

cd "$(dirname "$0")/../.."
ROOT=$(pwd)

if [ -z "$ONLY_RUN" ]; then
    NGX_MRUBY_CFLAGS="-DMRB_USE_MALLOC_TRIM $NGX_MRUBY_CFLAGS" \
        RELEASE_CC_OPT=-DNGX_MRUBY_DEBUG_STATS \
        RELEASE_GEM_LOCK= \
        sh "$ROOT/test/build_release.sh" "$ROOT" "$ROOT/build_soak"
fi

# The checks of the mock LLM upstream that the agent_* scenarios use (no
# nginx; about a second).
ruby "$ROOT/test/soak/mock_llm_test.rb"

exec ruby "$ROOT/test/soak/soak.rb"
