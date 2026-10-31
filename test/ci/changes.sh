#!/bin/sh
#
# Which kinds of files a change touches, and so which CI jobs it needs
# (docs/test/README.md, "Which jobs a run starts"). Every workflow that
# decides by the kind of change reads this script, so that the policy
# changes in this one file.
#
#   sh test/ci/changes.sh BASE HEAD   # the files that HEAD changes against BASE
#   sh test/ci/changes.sh --files     # the paths on stdin, one per line (tests)
#
# The output is one key=value line per key, each value true or false except
# that of build. The script is the same on master and next; the workflows
# that read it are not. What each category runs in a ready pull request:
#
#   code       src/, mrbgems/, mruby/, dependence/, build_config.rb,
#              build_config.rb.lock, configure, configure.in, config.in,
#              Makefile.in, build.sh, nginx_version, and every path that no
#              other category names (fail closed: a file of a new kind runs
#              everything until a category names it). test.yml runs the
#              whole build matrix with the sanitizer cell and the cell under
#              valgrind, and perf, and on next soak; codeql.yml scans src/
#              and mrbgems/. On next, nginx-tests.yml and examples.yml run
#              by their own path filters.
#   tests      test/, test.sh and .github/workflows/test.yml. test.yml runs
#              three cells of the build matrix: nginx 1.30.6 with the static
#              module, 1.31.8 with the dynamic module, and the cell that runs
#              nginx under valgrind.
#   docs       docs/, the Markdown files at the top, AUTHORS, LEGAL,
#              LICENSE and MITL. On next, site.yml builds the site and runs
#              its static checks, and its browser lanes when
#              site/scripts/ci-plan.mjs selects pages. On master, site-v2.yml
#              checks the 2.x pages; it runs on every ready pull request,
#              whatever it changes.
#   site       site/ and .github/workflows/site.yml, which only next has.
#              site.yml runs its build, its static checks and its browser
#              lanes.
#   examples   examples/, which only next has. examples.yml runs the
#              examples; site.yml builds the site and runs its static checks.
#   workflows  .github/ except test.yml and site.yml. zizmor.yml checks
#              all the workflows (these two included), and
#              codeql.yml the workflow files.
#   soak       code, test/soak/ or test/build_release.sh: on next, test.yml
#              runs the soak job. master has no soak job, so soak starts
#              nothing there.
#   perf       code, or the measurement of the performance comparison
#              (test/perf/, test/build_release.sh and the scenario files of
#              test/soak/): the perf job of test.yml compares.
#   build      full when code is true, tests when tests is true and code is
#              not, none otherwise.
#
# A renamed file is listed under its old and its new path
# (git diff --no-renames), so that moving a file of one kind under another
# counts for both. A path that git quotes (unusual characters) names no
# category, and so counts as code. Diagnostics go to stderr.

set -eu

if [ "$#" -eq 1 ] && [ "$1" = --files ]; then
    list=$(cat)
elif [ "$#" -eq 2 ]; then
    list=$(git diff --no-renames --name-only "$1" "$2" --)
else
    echo "usage: sh test/ci/changes.sh BASE HEAD, or sh test/ci/changes.sh --files < paths" >&2
    exit 2
fi

code=false tests=false docs=false site=false examples=false workflows=false
soak=false perf=false
count=0

classify() {
    case "$1" in
        .github/workflows/test.yml) tests=true ;;
        .github/workflows/site.yml) site=true ;;
        .github/*) workflows=true ;;
        src/* | mrbgems/* | mruby/* | dependence/* | build_config.rb | build_config.rb.lock | \
            configure | configure.in | config.in | Makefile.in | build.sh | nginx_version)
            code=true ;;
        test/* | test.sh) tests=true ;;
        docs/* | AUTHORS | LEGAL | LICENSE | MITL) docs=true ;;
        site/*) site=true ;;
        examples/*) examples=true ;;
        */*)
            echo "changes: $1 is in no category: counted as code" >&2
            code=true ;;
        *.md) docs=true ;;
        *)
            echo "changes: $1 is in no category: counted as code" >&2
            code=true ;;
    esac
    case "$1" in
        test/soak/* | test/build_release.sh) soak=true ;;
    esac
    case "$1" in
        test/perf/* | test/build_release.sh | test/soak/nginx.conf | test/soak/nginx.agent.conf | \
            test/soak/scenarios.rb | test/soak/http_client.rb | test/soak/mock_llm.rb | test/soak/handlers/*)
            perf=true ;;
    esac
}

# The loop reads a here-document, not a pipe, so that it runs in this shell
# and its assignments stay.
while IFS= read -r path; do
    [ -n "$path" ] || continue
    count=$((count + 1))
    classify "$path"
done <<EOF
$list
EOF

if [ "$code" = true ]; then
    soak=true perf=true build=full
elif [ "$tests" = true ]; then
    build=tests
else
    build=none
fi

echo "changes: ${count} files" >&2
printf 'code=%s\ntests=%s\ndocs=%s\nsite=%s\nexamples=%s\nworkflows=%s\nsoak=%s\nperf=%s\nbuild=%s\n' \
    "$code" "$tests" "$docs" "$site" "$examples" "$workflows" "$soak" "$perf" "$build"
