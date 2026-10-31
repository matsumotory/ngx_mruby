#!/bin/sh
#
# Cases for test/ci/changes.sh. Exits 1 on the first wrong answer.
#
#   sh test/ci/changes_test.sh

set -eu

cd "$(dirname "$0")/../.."
script=test/ci/changes.sh
failed=0

# expect NAME EXPECTED PATHS...: the output of --files for the paths, as
# one line of key=value pairs, must be EXPECTED.
expect() {
    name=$1 expected=$2
    shift 2
    actual=$(printf '%s\n' "$@" | sh "$script" --files 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
    if [ "$actual" = "$expected" ]; then
        echo "ok: $name"
    else
        echo "FAIL: $name"
        echo "  expected: $expected"
        echo "  actual:   $actual"
        failed=1
    fi
}

expect "docs only" \
    "code=false tests=false docs=true site=false examples=false workflows=false soak=false perf=false build=none" \
    docs/directives/README.md README.md AUTHORS
expect "src" \
    "code=true tests=false docs=false site=false examples=false workflows=false soak=true perf=true build=standard" \
    src/http/ngx_http_mruby_module.c
expect "test only" \
    "code=false tests=true docs=false site=false examples=false workflows=false soak=false perf=false build=standard" \
    test/t/ngx_mruby.rb test.sh
expect "test.yml is tests, another workflow is workflows" \
    "code=false tests=true docs=false site=false examples=false workflows=true soak=false perf=false build=standard" \
    .github/workflows/test.yml .github/workflows/codeql.yml
expect "site.yml is site" \
    "code=false tests=false docs=false site=true examples=false workflows=false soak=false perf=false build=none" \
    .github/workflows/site.yml
expect "the other files of .github are workflows" \
    "code=false tests=false docs=false site=false examples=false workflows=true soak=false perf=false build=none" \
    .github/workflows/zizmor.yml .github/dependabot.yml .github/PULL_REQUEST_TEMPLATE.md
expect "soak scenarios" \
    "code=false tests=true docs=false site=false examples=false workflows=false soak=true perf=true build=standard" \
    test/soak/scenarios.rb
expect "soak driver only" \
    "code=false tests=true docs=false site=false examples=false workflows=false soak=true perf=false build=standard" \
    test/soak/soak.rb
expect "the check of the mock LLM alone runs soak" \
    "code=false tests=true docs=false site=false examples=false workflows=false soak=true perf=false build=standard" \
    test/soak/mock_llm_test.rb
expect "perf only" \
    "code=false tests=true docs=false site=false examples=false workflows=false soak=false perf=true build=standard" \
    test/perf/perf.rb
expect "site and examples" \
    "code=false tests=false docs=false site=true examples=true workflows=false soak=false perf=false build=none" \
    site/src/layout.mjs examples/start/README.md
expect "unknown path at the top is code" \
    "code=true tests=false docs=false site=false examples=false workflows=false soak=true perf=true build=standard" \
    Dockerfile
expect "unknown directory is code" \
    "code=true tests=false docs=false site=false examples=false workflows=false soak=true perf=true build=standard" \
    misc/foo.txt
expect "Markdown below the top is not docs" \
    "code=true tests=false docs=false site=false examples=false workflows=false soak=true perf=true build=standard" \
    example/README.md
expect "build files" \
    "code=true tests=false docs=false site=false examples=false workflows=false soak=true perf=true build=standard" \
    build_config.rb.lock configure.in
expect "nothing changed" \
    "code=false tests=false docs=false site=false examples=false workflows=false soak=false perf=false build=none"

# expect_run NAME EXPECTED PATHS ARGS...: the output for the options ARGS
# of the run, with PATHS (one per line, possibly empty) on stdin, must be
# EXPECTED. ARGS ends with --files when the run reads the paths.
expect_run() {
    name=$1 expected=$2 paths=$3
    shift 3
    actual=$(printf '%s' "$paths" | sh "$script" "$@" 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
    if [ "$actual" = "$expected" ]; then
        echo "ok: $name"
    else
        echo "FAIL: $name"
        echo "  expected: $expected"
        echo "  actual:   $actual"
        failed=1
    fi
}

# The runs: which give every cell (full), and which none.
expect_run "a label other than full-matrix changes nothing" \
    "code=true tests=false docs=false site=false examples=false workflows=false soak=true perf=true build=standard" \
    src/http/ngx_http_mruby_module.c --label perf --label 'with space' --files
expect_run "the label full-matrix on a docs change: every cell and soak" \
    "code=false tests=false docs=true site=false examples=false workflows=false soak=true perf=false build=full" \
    docs/releases/v3.0.0.md --label full-matrix --files
expect_run "the label full-matrix on a code change" \
    "code=true tests=false docs=false site=false examples=false workflows=false soak=true perf=true build=full" \
    src/http/ngx_http_mruby_module.c --label perf --label full-matrix --files
expect_run "a draft runs nothing" \
    "code=false tests=false docs=false site=false examples=false workflows=false soak=false perf=false build=none" \
    '' --draft
expect_run "a push to a branch runs nothing" \
    "code=false tests=false docs=false site=false examples=false workflows=false soak=false perf=false build=none" \
    '' --push
expect_run "a tag runs every cell" \
    "code=false tests=false docs=false site=false examples=false workflows=false soak=true perf=true build=full" \
    '' --tag
expect_run "Run workflow without base runs every cell" \
    "code=false tests=false docs=false site=false examples=false workflows=false soak=true perf=true build=full" \
    '' --dispatch
expect_run "Run workflow with valgrind (the nightly run) runs every cell" \
    "code=false tests=false docs=false site=false examples=false workflows=false soak=true perf=true build=full" \
    '' --dispatch --valgrind
expect_run "Run workflow with valgrind and base still runs every cell" \
    "code=false tests=true docs=false site=false examples=false workflows=false soak=true perf=true build=full" \
    test.sh --dispatch --valgrind --files
expect_run "Run workflow with base (the dry run) of code: standard" \
    "code=true tests=false docs=false site=false examples=false workflows=false soak=true perf=true build=standard" \
    src/http/ngx_http_mruby_module.c --dispatch --files
expect_run "Run workflow with base of docs: none" \
    "code=false tests=false docs=true site=false examples=false workflows=false soak=false perf=false build=none" \
    README.md --dispatch --files

# Options that do not describe one run are an error, not a decision.
for args in "--draft --files" "--push --files" "--tag --files" "--draft --tag" \
    "--dispatch --push" "--valgrind" "--valgrind --files" "--label full-matrix --draft" \
    "--label" "--label full-matrix" "--bogus --files"; do
    # shellcheck disable=SC2086 # the words of $args are the options
    if printf 'src/x.c\n' | sh "$script" $args > /dev/null 2>&1; then
        echo "FAIL: options '$args' must be an error"
        failed=1
    else
        echo "ok: options '$args' are an error"
    fi
done

# A renamed file, from git: the old and the new path both count, so moving
# a source file under docs/ still builds.
repo=$(mktemp -d)
trap 'rm -rf "$repo"' EXIT
git -C "$repo" init -q
mkdir -p "$repo/src" "$repo/docs"
echo 'int x;' > "$repo/src/x.c"
git -C "$repo" add src/x.c
git -C "$repo" -c user.name=t -c user.email=t@example.invalid commit -q -m base
git -C "$repo" mv src/x.c docs/x.c
git -C "$repo" -c user.name=t -c user.email=t@example.invalid commit -q -m move
actual=$(cd "$repo" && sh "$OLDPWD/$script" HEAD^ HEAD 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
expected="code=true tests=false docs=true site=false examples=false workflows=false soak=true perf=true build=standard"
if [ "$actual" = "$expected" ]; then
    echo "ok: renamed file under both paths"
else
    echo "FAIL: renamed file under both paths"
    echo "  expected: $expected"
    echo "  actual:   $actual"
    failed=1
fi

# A wrong argument is an error, not a decision.
if sh "$script" only-one > /dev/null 2>&1; then
    echo "FAIL: one argument must be an error"
    failed=1
else
    echo "ok: one argument is an error"
fi
# A revision that does not exist is an error, not "nothing changed".
if sh "$script" 0000000000000000000000000000000000000000 HEAD > /dev/null 2>&1; then
    echo "FAIL: a missing revision must be an error"
    failed=1
else
    echo "ok: a missing revision is an error"
fi

exit "$failed"
