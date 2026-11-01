#!/bin/sh
#
# The checks of the site that a pull request runs locally before it is
# marked ready ("Site CI" in docs/test/README.md). Pull requests do not run
# site.yml: the owner decided on 2026-11-02 that CI does not repeat the
# checks that run locally. This script runs the checks of the build job of
# site.yml, in its order, and every browser check, which no CI job runs.
#
#   npm run check:ci        # in site/: everything below
#   npm run check:browser   # in site/: the browser checks only, on the
#                           # dist/ of an earlier build (with dist/v2/)
#
# The 2.x pages under /v2/ are built from a work tree of master:
# NGX_MRUBY_V2_TREE names one. Without it, the script makes a clone of
# origin/master of this repository in site/generated/v2-tree (ignored by
# git; run git fetch origin master first), as site.yml checks out master.
# The Ruby blocks of the pages are compiled with the mrbc of the bundled
# mruby: MRBC names it, or mruby/build/host/bin/mrbc of this checkout is
# used when it exists; without either, that check is skipped and the
# script says so at the end. The browser checks need Chromium and WebKit
# for the playwright of package-lock.json (npx playwright install chromium
# webkit). Japanese text is measured in the served Noto Sans JP
# (--ja-face noto), as CI on Linux renders it.
#
# The fresh-clone build and the build with network access blocked stay in
# the run of site.yml on the push to next. Run them locally
# (sh scripts/check-fresh-clone.sh, npm run check:offline) when a change
# touches package.json, package-lock.json or the build scripts.
#
# It stops at the first failed check, with its exit status.

set -eu

site=$(cd "$(dirname "$0")/.." && pwd)
repo=$(cd "$site/.." && pwd)
cd "$site"

mode=all
case "${1-}" in
    '') ;;
    --browser) mode=browser ;;
    *) echo "usage: sh scripts/check-ci.sh [--browser]" >&2; exit 2 ;;
esac

started=$(date +%s)
skipped=''
run() {
    echo
    echo "== check:ci: $*"
    "$@"
}
skip() {
    echo
    echo "== check:ci: SKIP $1"
    skipped="$skipped
  - $1"
}

static_checks() {
    run npm run build
    # The 2.x pages, from the tree of NGX_MRUBY_V2_TREE or a clone of
    # origin/master.
    if [ -n "${NGX_MRUBY_V2_TREE-}" ]; then
        tree=$NGX_MRUBY_V2_TREE
    else
        sha=$(git -C "$repo" rev-parse --verify --quiet 'origin/master^{commit}') || {
            echo "check:ci: no origin/master in $repo: run git fetch origin master, or set NGX_MRUBY_V2_TREE to a work tree of master" >&2
            exit 2
        }
        tree=$site/generated/v2-tree
        if [ ! -d "$tree/.git" ]; then
            rm -rf "$tree"
            git clone --quiet --shared --no-checkout "$repo" "$tree"
        fi
        git -C "$tree" checkout --quiet --force --detach "$sha"
        echo "check:ci: the 2.x pages from origin/master $sha"
    fi
    run node scripts/build-v2.mjs --tree "$tree"
    run npm test
    # The relative links and anchors of the Markdown files that git
    # tracks, outside the vendored trees.
    echo
    echo "== check:ci: check_links.py on the Markdown files that git tracks"
    (cd "$repo" && git ls-files -z -- '*.md' ':!:mruby/' ':!:dependence/' | xargs -0 python3 site/scripts/check_links.py .)
    # check-built-links, check-project-badges, check-pages, check-japanese,
    # check-no-js, check-css, check-home, check-diagrams, check-samples,
    # check-reference, check-deploy and check-docs-export.
    run npm run check
    run python3 scripts/contrast.py
    mrbc=${MRBC-}
    if [ -z "$mrbc" ] && [ -x "$repo/mruby/build/host/bin/mrbc" ]; then
        mrbc=$repo/mruby/build/host/bin/mrbc
    fi
    if [ -n "$mrbc" ]; then
        run node scripts/check-ruby-blocks.mjs --mrbc "$mrbc"
    else
        skip "check-ruby-blocks.mjs: no mrbc (set MRBC, or build one in about ten seconds: cd mruby && MRUBY_CONFIG=build_config/mrbc.rb MRUBY_BUILD_DIR=DIR rake, then MRBC=DIR/mrbc/bin/mrbc)"
    fi
    run node scripts/check-v2.mjs --no-browser
}

# Every check that the browser lanes of site.yml ran until 2026-11-02, on
# every page.
browser_checks() {
    run node scripts/check-styles.mjs --ja-face noto
    run node scripts/check-japanese-lines.mjs --ja-face noto
    run node scripts/check-japanese-lines.mjs --ja-face noto --pages /v2/ja/
    run node scripts/check-copy-idle.mjs
    run node scripts/check-home-interaction.mjs
    run node scripts/check-code-layout.mjs
    run node scripts/check-focus.mjs
    run node scripts/check-language-links.mjs
    run node scripts/check-lighthouse.mjs
    run node scripts/check-project-badges.mjs --browser
    run node scripts/check-search-identifiers.mjs
    run node scripts/check-v2.mjs
    run node scripts/test-read-only-browser.mjs
    run node scripts/screenshots.mjs --out build-screenshots
    run node scripts/screenshots-live.mjs --local --out build-screenshots/predeploy-smoke
}

if [ "$mode" = all ]; then
    static_checks
fi
browser_checks

echo
echo "check:ci: passed in $(( $(date +%s) - started )) s ($mode)"
if [ -n "$skipped" ]; then
    echo "check:ci: skipped:$skipped"
fi
