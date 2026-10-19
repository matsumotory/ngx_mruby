#!/bin/sh

# nginx's own test suite (https://github.com/nginx/nginx-tests) against nginx
# built with ngx_mruby, and against nginx of the same version and configure
# options without ngx_mruby, so that the failures of the first run can be told
# from those of nginx itself. See "nginx-tests" in docs/test/README.md.
#
#   sh test/nginx-tests/run.sh [configure options for test.sh]
#
# Run it from the top of the checkout, on Linux, as a user other than root
# (nginx-tests writes its configuration and files to directories that only
# that user can read, and nginx started by root runs its workers as nobody).
#
# Environment:
#   NGINX_TESTS_OUT   output directory (default build_nginxtests)
#   NGINX_TESTS_SRC   an nginx-tests checkout at NGINX_TESTS_COMMIT to use
#                     instead of fetching it (for example when github.com is
#                     unreachable)
#   NGINX_TESTS_JOBS  parallel test files of prove (default: the number of CPUs)
#   NGINX_TESTS_FILES test files to run instead of all (for example "access.t")
#   NGX_MRUBY_COMMIT  the ngx_mruby commit that the summary names (default:
#                     GITHUB_SHA in GitHub Actions, else HEAD of the checkout)
#
# Output, in NGINX_TESTS_OUT:
#   mruby/prove.log, plain/prove.log  the output of prove for each build
#   mruby/results.tsv, plain/...      one line per test file: file, result, detail
#   summary.md                        counts and the lists of failed files
#   only-mruby.txt, both.txt, only-plain.txt  the failed files by build
#
# The exit status is 0 when both builds were tested and the results were read,
# also when test files failed; it is not 0 when a build, the fetch or prove
# itself failed, or when a log has no result line of prove.

set -e

# nginx-tests has no releases or tags. The commit is pinned so that a new test
# upstream does not change the results of this job without a change here; move
# it in a pull request of its own, with the results before and after.
# ec44bc80c4bf: the head of master on 2026-10-19 (committed 2026-10-16).
NGINX_TESTS_REPO=https://github.com/nginx/nginx-tests
NGINX_TESTS_COMMIT=ec44bc80c4bfac1dbd8ffee3875101285f8502ac

if [ ! -f ./nginx_version ] || [ ! -f ./test.sh ]; then
    echo "run.sh: run it from the top of the ngx_mruby checkout" >&2
    exit 1
fi
if [ "$(id -u)" = 0 ]; then
    echo "run.sh: run it as a user other than root (see the comment at the top)" >&2
    exit 1
fi

. ./nginx_version

TOP=$(pwd)
OUT=${NGINX_TESTS_OUT:-build_nginxtests}
case "$OUT" in /*) ;; *) OUT="$TOP/$OUT" ;; esac
JOBS=${NGINX_TESTS_JOBS:-$(getconf _NPROCESSORS_ONLN)}
HERE="$TOP/test/nginx-tests"
mkdir -p "$OUT"

# nginx-tests at the pinned commit.
if [ -n "$NGINX_TESTS_SRC" ]; then
    SUITE=$NGINX_TESTS_SRC
else
    SUITE="$OUT/nginx-tests"
    if [ "$(git -C "$SUITE" rev-parse HEAD 2>/dev/null)" != "$NGINX_TESTS_COMMIT" ]; then
        rm -rf "$SUITE"
        git init -q "$SUITE"
        git -C "$SUITE" fetch -q --depth 1 "$NGINX_TESTS_REPO" "$NGINX_TESTS_COMMIT"
        git -C "$SUITE" -c advice.detachedHead=false checkout -q FETCH_HEAD
    fi
fi
suite_commit=$(git -C "$SUITE" rev-parse HEAD)
if [ "$suite_commit" != "$NGINX_TESTS_COMMIT" ]; then
    echo "run.sh: $SUITE is at $suite_commit, expected $NGINX_TESTS_COMMIT" >&2
    exit 1
fi

# nginx with ngx_mruby, built as test.sh builds it (static module, the
# configure options of test.sh, -DMRB_GC_STRESS), installed to build/nginx.
# BUILD_DYNAMIC_MODULE would make test.sh build into build_dynamic/ and leave
# build/nginx as it was, so it is unset: the run is of the static module.
echo "run.sh: building nginx with ngx_mruby (test.sh)"
unset BUILD_DYNAMIC_MODULE
TEST_SH_SKIP_TESTS=1 sh ./test.sh "$@"
MRUBY_NGINX="$TOP/build/nginx/sbin/nginx"

# nginx without ngx_mruby: the same nginx source and the configure options
# that test.sh gave nginx (NGX_CONFIG_OPT of the generated Makefile), without
# the two --add-module options that the Makefile adds (ngx_mruby and
# ngx_devel_kit). make runs that configure line in sh, so the value is split
# here by sh in the same way.
config_opt=$(sed -n 's/^NGX_CONFIG_OPT=//p' Makefile)
if [ -z "$config_opt" ]; then
    echo "run.sh: no NGX_CONFIG_OPT in Makefile" >&2
    exit 1
fi
PLAIN_SRC="$OUT/plain/src"
stamp="$NGINX_SRC_VER $config_opt"
if [ ! -x "$PLAIN_SRC/objs/nginx" ] || [ "$(cat "$OUT/plain/build_stamp" 2>/dev/null)" != "$stamp" ]; then
    echo "run.sh: building nginx without ngx_mruby"
    rm -rf "$OUT/plain"
    mkdir -p "$OUT/plain"
    cp -R "build/$NGINX_SRC_VER" "$PLAIN_SRC"
    rm -rf "$PLAIN_SRC/objs" "$PLAIN_SRC/Makefile"
    if [ -x "$PLAIN_SRC/configure" ]; then configure=./configure; else configure=./auto/configure; fi
    (
        cd "$PLAIN_SRC"
        eval "set -- $config_opt"
        $configure "$@" > "$OUT/plain/configure.log" 2>&1 || { tail -n 50 "$OUT/plain/configure.log"; exit 1; }
        make -j "$JOBS" > "$OUT/plain/make.log" 2>&1 || { tail -n 50 "$OUT/plain/make.log"; exit 1; }
    )
    printf '%s\n' "$stamp" > "$OUT/plain/build_stamp"
fi
PLAIN_NGINX="$PLAIN_SRC/objs/nginx"

# prove for each build. The test files read TEST_NGINX_BINARY; each file
# starts its own nginx in a temporary directory, on ports that it locks, so
# files run in parallel.
for build in mruby plain; do
    if [ "$build" = mruby ]; then binary=$MRUBY_NGINX; else binary=$PLAIN_NGINX; fi
    mkdir -p "$OUT/$build"
    "$binary" -V > "$OUT/$build/nginx-V.txt" 2>&1
    echo "run.sh: prove on the build $build ($binary), $JOBS jobs"
    status=0
    (
        cd "$SUITE"
        # shellcheck disable=SC2086
        TEST_NGINX_BINARY="$binary" prove -j "$JOBS" ${NGINX_TESTS_FILES:-.}
    ) > "$OUT/$build/prove.log" 2>&1 || status=$?
    echo "run.sh: prove on the build $build exited with $status"
    perl "$HERE/results.pl" "$OUT/$build/prove.log" > "$OUT/$build/results.tsv"
done

head=${NGX_MRUBY_COMMIT:-${GITHUB_SHA:-}}
if [ -z "$head" ]; then
    if [ "$(git -C "$TOP" rev-parse --show-toplevel 2>/dev/null)" = "$TOP" ]; then
        head=$(git -C "$TOP" rev-parse HEAD)
    else
        head="unknown (not a git checkout)"
    fi
fi
perl "$HERE/compare.pl" "$OUT" "$suite_commit" "$NGINX_SRC_VER" "$head"
