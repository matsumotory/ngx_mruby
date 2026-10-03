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
# Some inputs of the build are not tracked by make and rake, so run.sh
# records them in build_soak/build_stamp and builds mruby and nginx from
# scratch when they change (see the comment at the stamp below). For a change
# that the stamp does not cover, `rm -rf build_soak` resets the soak build.
#
# Layout:
#   build_soak/tree          copy of the sources; the nginx source is in build_soak/tree/build
#   build_soak/nginx         nginx installed by `make install`
#   build_soak/nginx/soak    runtime prefix of the soak test (conf/, logs/)
#   build_soak/build_stamp   the untracked inputs of the last build

set -e

cd "$(dirname "$0")/../.."
ROOT=$(pwd)
SOAK_BUILD="$ROOT/build_soak"
TREE="$SOAK_BUILD/tree"

if [ -z "$ONLY_RUN" ]; then
    # build_config.rb passes NGX_MRUBY_CFLAGS to the mruby build.
    NGX_MRUBY_CFLAGS="-DMRB_USE_MALLOC_TRIM $NGX_MRUBY_CFLAGS"
    export NGX_MRUBY_CFLAGS
    # nginx's configure splits --with-cc-opt again in the shell that make
    # runs, so the spaces are escaped (as test.sh does).
    NGINX_CC_OPT='-g\ -O2\ -fno-common\ -DNGX_MRUBY_DEBUG_STATS'
    NGINX_CONFIG_OPT_ENV="--prefix=$SOAK_BUILD/nginx --with-http_stub_status_module --with-cc-opt=$NGINX_CC_OPT"
    export NGINX_CONFIG_OPT_ENV
    TOP_FILES="configure config.in Makefile.in build.sh build_config.rb nginx_version"

    # The stamp lists the inputs of the build that make and rake do not
    # track:
    # - The mruby tree. test.sh drops a stale mruby build through
    #   .mruby_version (Makefile.in), which needs .git in the build
    #   directory, and the copy has none. mruby archives with `ar rs`, so the
    #   objects of removed or renamed sources would stay in libmruby.a. The
    #   tree id comes from git when the repository is available (it does not
    #   see uncommitted changes), else from a checksum of the files.
    # - The file names under mrbgems/, for the same reason.
    # - The top-level build files: build_config.rb (a dropped gem stays in
    #   libmruby.a as well), config.in, configure and build.sh (the sources
    #   and options of nginx's configure), Makefile.in and nginx_version.
    # - NGX_MRUBY_CFLAGS: rake does not rebuild mruby when only they change.
    # - The nginx options. nginx's configure runs only when objs/Makefile is
    #   missing, so later runs would keep the options of the first one.
    # When the stamp differs from that of the last build, the mruby build
    # (with the gem clones), the gem lock file and nginx's objs/ are removed,
    # which makes the next steps build both from scratch, as on a fresh
    # checkout. The downloaded nginx source is kept.
    if ! mruby_tree=$(git -C "$ROOT" rev-parse -q --verify HEAD:mruby 2>/dev/null); then
        mruby_tree=$(find mruby -path mruby/build -prune -o -type f -exec cksum {} + | LC_ALL=C sort | cksum)
    fi
    # TOP_FILES is a list of names and is split on purpose.
    stamp=$(
        printf 'mruby: %s\n' "$mruby_tree"
        printf 'mrbgems: %s\n' "$(find mrbgems -type f | LC_ALL=C sort | cksum)"
        cksum $TOP_FILES
        printf 'NGX_MRUBY_CFLAGS: %s\n' "$NGX_MRUBY_CFLAGS"
        printf 'NGINX_CONFIG_OPT_ENV: %s\n' "$NGINX_CONFIG_OPT_ENV"
    )
    mkdir -p "$TREE/mruby"
    if [ "$(cat "$SOAK_BUILD/build_stamp" 2>/dev/null)" != "$stamp" ]; then
        if [ -e "$SOAK_BUILD/build_stamp" ]; then
            echo "run.sh: the build inputs changed; building mruby and nginx from scratch"
        fi
        rm -rf "$TREE/mruby/build" "$TREE/build_config.rb.lock" "$TREE"/build/*/objs
        printf '%s\n' "$stamp" > "$SOAK_BUILD/build_stamp"
    fi

    for f in $TOP_FILES; do
        cp -p "$f" "$TREE/"
    done
    # Replace whole directories, so that files deleted here are deleted in
    # the copy too. mruby/build is the output of the test.sh build.
    for d in src mrbgems dependence mruby/*; do
        [ "$d" = mruby/build ] && continue
        rm -rf "${TREE:?}/$d"
        cp -pR "$d" "$TREE/$(dirname "$d")/"
    done

    # build.sh also reads these. The soak build is always a static module,
    # built from its own nginx source and the system OpenSSL. (The CI
    # workflow sets OPENSSL_SRC_VERSION for every job.)
    unset BUILD_DYNAMIC_MODULE NGINX_SRC_ENV OPENSSL_SRC_VERSION

    (
        cd "$TREE"
        sh build.sh
        make install
    )
fi

exec ruby "$ROOT/test/soak/soak.rb"
