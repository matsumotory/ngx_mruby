#!/bin/sh
#
# Build ngx_mruby for the memory soak test and run it. Linux only: the driver
# reads /proc. See docs/test/README.md, "Soak test for memory".
#
#   sh test/soak/run.sh              # build (incremental after the first run), then run
#   ONLY_RUN=1 sh test/soak/run.sh   # run against the existing build
#
# The soak build is not the test.sh build. It defines NGX_MRUBY_DEBUG_STATS
# (which adds the Nginx::Debug class), compiles nginx and ngx_mruby with
# -O2 -g, and has neither MRB_GC_STRESS nor --with-debug, so that the memory
# use of the worker is close to that of a production build. mruby is built
# with MRB_USE_MALLOC_TRIM: mrb_full_gc() then calls malloc_trim(0), so the
# full GC that Nginx::Debug.gc runs before each sample also returns the free
# pages of the C heap, and VmRSS follows the memory in use instead of where
# the allocator happened to leave free memory. Without a call to
# GC.start or Nginx::Debug.gc, mruby runs a full GC only in rare cases
# (too many objects in one incremental GC, or a failed allocation).
#
# Why build.sh and not test.sh: test.sh always adds -DMRB_GC_STRESS, -O0 and
# --with-debug, and kills every running nginx. build.sh takes the nginx
# configure options from NGINX_CONFIG_OPT_ENV and adds no flags of its own,
# so the soak build sets its options without changing either script.
#
# Why a copy of the sources: configure writes Makefile, config and
# mrbgems_config into the directory it runs in, and mruby builds into
# mruby/build. Running build.sh in the repository root would replace the
# files that `ONLY_BUILD_NGX_MRUBY=1 sh test.sh` reuses, and the soak build
# and the test.sh build would share one mruby build, with and without
# MRB_GC_STRESS. build.sh therefore runs in build_soak/tree. The copy keeps
# the modification times, so make and rake rebuild only what changed.
#
# Layout:
#   build_soak/tree          copy of the sources; the nginx source is in build_soak/tree/build
#   build_soak/nginx         nginx installed by `make install`
#   build_soak/nginx/soak    runtime prefix of the soak test (conf/, logs/)

set -e

cd "$(dirname "$0")/../.."
ROOT=$(pwd)
SOAK_BUILD="$ROOT/build_soak"
TREE="$SOAK_BUILD/tree"

if [ -z "$ONLY_RUN" ]; then
    mkdir -p "$TREE/mruby"
    for f in configure config.in Makefile.in build.sh build_config.rb nginx_version; do
        cp -p "$f" "$TREE/"
    done
    # Replace whole directories, so that files deleted here are deleted in
    # the copy too. mruby/build is the output of the test.sh build.
    for d in src mrbgems dependence mruby/*; do
        [ "$d" = mruby/build ] && continue
        rm -rf "${TREE:?}/$d"
        cp -pR "$d" "$TREE/$(dirname "$d")/"
    done

    # build_config.rb passes NGX_MRUBY_CFLAGS to the mruby build. rake does
    # not rebuild mruby when only these flags change, so the mruby build is
    # removed when they differ from those of the last build.
    NGX_MRUBY_CFLAGS="-DMRB_USE_MALLOC_TRIM $NGX_MRUBY_CFLAGS"
    export NGX_MRUBY_CFLAGS
    if [ "$(cat "$SOAK_BUILD/mruby_cflags" 2>/dev/null)" != "$NGX_MRUBY_CFLAGS" ]; then
        rm -rf "$TREE/mruby/build/host"
        printf '%s\n' "$NGX_MRUBY_CFLAGS" > "$SOAK_BUILD/mruby_cflags"
    fi

    # nginx's configure splits --with-cc-opt again in the shell that make
    # runs, so the spaces are escaped (as test.sh does).
    NGINX_CC_OPT='-g\ -O2\ -fno-common\ -DNGX_MRUBY_DEBUG_STATS'
    (
        cd "$TREE"
        NGINX_CONFIG_OPT_ENV="--prefix=$SOAK_BUILD/nginx --with-http_stub_status_module --with-cc-opt=$NGINX_CC_OPT" \
            sh build.sh
        make install
    )
fi

exec ruby "$ROOT/test/soak/soak.rb"
