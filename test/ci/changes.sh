#!/bin/sh
#
# Which kinds of files a change touches, and so which CI jobs it needs
# (docs/test/README.md, "Which jobs a run starts"). Every workflow that
# decides by the kind of change reads this script, so that the policy
# changes in this one file.
#
#   sh test/ci/changes.sh [RUN] BASE HEAD   # the files that HEAD changes against BASE
#   sh test/ci/changes.sh [RUN] --files     # the paths on stdin, one per line (tests)
#   sh test/ci/changes.sh RUN               # a run that reads no files
#
# RUN says which run of test.yml asks, from the event of the run. Without
# it, the run is a ready pull request without labels, which is what the
# other workflows and condition 2 of "Review and merge" in AGENTS.md ask.
#
#   --label NAME  a label of the ready pull request, one option per label.
#                 The label full-matrix gives build full (the check pull
#                 request before a tag, "Before the tag" in
#                 docs/releases/README.md); other labels change nothing.
#   --draft       a draft pull request: no files, build none.
#   --push        a push to a branch (master, next, v*.x): no files, build
#                 none. These branches take changes only through pull
#                 requests, whose runs tested them.
#   --tag         a push of a tag: no files, build full.
#   --dispatch    "Run workflow". With files (the input base), as for a
#                 ready pull request without labels (the dry run); without
#                 files, build full.
#   --valgrind    with --dispatch: the input valgrind (the nightly run),
#                 build full, with or without files.
#
# The output is one key=value line per key, each value true or false except
# that of build. A run that reads no files gives false for every category.
# The script is the same on master and next; the workflows that read it
# are not. What each category runs in a ready pull request:
#
#   code       src/, mrbgems/, mruby/, dependence/, build_config.rb,
#              build_config.rb.lock, configure, configure.in, config.in,
#              Makefile.in, build.sh, nginx_version, and every path that no
#              other category names (fail closed: a file of a new kind runs
#              everything until a category names it). test.yml runs the
#              four cells of build standard (the cell under valgrind and
#              the sanitizer cell among them), and perf, and on next soak;
#              codeql.yml scans src/ and mrbgems/. On next, nginx-tests.yml
#              and examples.yml run by their own path filters.
#   tests      test/, test.sh and .github/workflows/test.yml. test.yml runs
#              the four cells of build standard.
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
#              nothing there. A run with build full gives soak true.
#   perf       code, or the measurement of the performance comparison
#              (test/perf/, test/build_release.sh and the scenario files of
#              test/soak/): the perf job of test.yml compares.
#   build      the cells of the build matrix of test.yml: standard (four
#              cells: nginx 1.31.8 with the static module, 1.30.6 with the
#              dynamic module, the sanitizer cell and the cell under
#              valgrind) when code or tests is true; full (every cell) for
#              the label full-matrix, a tag, and "Run workflow" without
#              files or with the input valgrind; none otherwise.
#
# A renamed file is listed under its old and its new path
# (git diff --no-renames), so that moving a file of one kind under another
# counts for both. A path that git quotes (unusual characters) names no
# category, and so counts as code. Diagnostics go to stderr.

set -eu

usage() {
    echo "usage: sh test/ci/changes.sh [RUN] BASE HEAD, sh test/ci/changes.sh [RUN] --files < paths, or sh test/ci/changes.sh RUN" >&2
    echo "RUN: --label NAME (once per label), --draft, --push, --tag, or --dispatch [--valgrind]" >&2
    exit 2
}

# The run: pr (the default), draft, push, tag or dispatch. Two of them are
# an error, not a choice of one.
run='pr'
full_matrix_label=false
valgrind=false
labels=0
set_run() {
    if [ "$run" != pr ]; then
        echo "changes: --$1 and --$run are two runs" >&2
        usage
    fi
    run=$1
}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --label)
            [ "$#" -ge 2 ] || usage
            labels=$((labels + 1))
            if [ "$2" = full-matrix ]; then
                full_matrix_label=true
            fi
            shift 2 ;;
        --draft) set_run draft; shift ;;
        --push) set_run push; shift ;;
        --tag) set_run tag; shift ;;
        --dispatch) set_run dispatch; shift ;;
        --valgrind) valgrind=true; shift ;;
        --files) break ;;
        -*)
            echo "changes: unknown option $1" >&2
            usage ;;
        *) break ;;
    esac
done
if [ "$labels" -gt 0 ] && [ "$run" != pr ]; then
    echo "changes: --label is for a ready pull request, not --$run" >&2
    usage
fi
if [ "$valgrind" = true ] && [ "$run" != dispatch ]; then
    echo "changes: --valgrind needs --dispatch" >&2
    usage
fi

if [ "$#" -eq 1 ] && [ "$1" = --files ]; then
    files=true
    list=$(cat)
elif [ "$#" -eq 2 ]; then
    files=true
    list=$(git diff --no-renames --name-only "$1" "$2" --)
elif [ "$#" -eq 0 ]; then
    files=false
    list=
else
    usage
fi
# A ready pull request is decided by its files. Draft, push and tag runs
# read none, so files given to them are a mistake of the caller.
case "$run" in
    pr)
        [ "$files" = true ] || usage ;;
    draft | push | tag)
        if [ "$files" = true ]; then
            echo "changes: --$run reads no files" >&2
            usage
        fi ;;
esac

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
    soak=true perf=true build=standard
elif [ "$tests" = true ]; then
    build=standard
else
    build=none
fi

# The runs that build every cell, and those that build none, whatever the
# files say.
case "$run" in
    pr)
        if [ "$full_matrix_label" = true ]; then
            echo "changes: the label full-matrix: every cell and soak" >&2
            build=full soak=true
        fi ;;
    draft)
        echo "changes: a draft pull request: no build, soak or perf" >&2
        build=none soak=false perf=false ;;
    push)
        echo "changes: a push to a branch: the run of its pull request tested it; no build, soak or perf" >&2
        build=none soak=false perf=false ;;
    tag)
        echo "changes: a push of a tag: every cell and soak" >&2
        build=full soak=true perf=true ;;
    dispatch)
        if [ "$valgrind" = true ]; then
            echo "changes: Run workflow with the input valgrind: every cell and soak" >&2
            build=full soak=true perf=true
        elif [ "$files" = false ]; then
            echo "changes: Run workflow without the input base: every cell and soak" >&2
            build=full soak=true perf=true
        fi ;;
esac

if [ "$files" = true ]; then
    echo "changes: ${count} files" >&2
fi
printf 'code=%s\ntests=%s\ndocs=%s\nsite=%s\nexamples=%s\nworkflows=%s\nsoak=%s\nperf=%s\nbuild=%s\n' \
    "$code" "$tests" "$docs" "$site" "$examples" "$workflows" "$soak" "$perf" "$build"
