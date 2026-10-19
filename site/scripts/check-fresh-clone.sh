#!/bin/sh
# Check of step 1 (docs/proposals/site.md, section 6): a fresh clone builds
# with npm ci and npm run build.
#
#   sh site/scripts/check-fresh-clone.sh [--keep DIR] [REV]
#
# It clones the git repository of the current directory into a new
# directory with its whole history (git clone --no-local; the last-updated
# dates of the pages come from git log), checks out REV (default HEAD)
# there, and runs npm ci --ignore-scripts and npm run build in its site/.
# Only what REV commits takes part, so a file that is in the working tree
# but not committed, or a package-lock.json out of step with package.json,
# fails the check. The clone is removed afterwards, unless --keep DIR
# names the directory to make it in (DIR must not exist yet): the workflow
# site.yml keeps it, runs the other checks on its build and uploads it.
#
# --ignore-scripts keeps the install scripts of the packages from running.
# None of the packages that npm ci installs on Linux has one today (the
# only package of the lock flagged with one is fsevents, which installs on
# macOS alone). If an update of the lock brings one, the build either does
# not need it or fails here, in the review of that update, and its code
# does not run.
#
# npm ci needs the npm registry (or npm's cache); npm run build needs no
# network.
#
# Exit status: 0 when the build succeeds and writes dist/index.html, 1 when
# it fails, 2 on a usage error.

set -u
me=check-fresh-clone.sh

usage() {
  echo "usage: sh site/scripts/check-fresh-clone.sh [--keep DIR] [REV]" >&2
  exit 2
}

keep=
while [ $# -gt 0 ]; do
  case $1 in
    --keep)
      [ $# -ge 2 ] || usage
      keep=$2
      shift 2
      ;;
    -*) usage ;;
    *) break ;;
  esac
done
[ $# -le 1 ] || usage
rev=${1:-HEAD}

repo=$(git rev-parse --show-toplevel) || exit 2
if ! sha=$(git rev-parse --verify --quiet "$rev^{commit}"); then
  echo "$me: $rev is not a commit of $repo" >&2
  exit 2
fi
if [ -n "$keep" ]; then
  if [ -e "$keep" ]; then
    echo "$me: $keep exists" >&2
    exit 2
  fi
  clone=$keep
else
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/ngx_mruby-site.XXXXXX") || exit 2
  trap 'rm -rf "$tmp"' EXIT
  clone=$tmp/ngx_mruby
fi

fail() {
  echo "$me: $1 (a clone of $sha in $clone)"
  exit 1
}

echo "$me: cloning $repo at $sha into $clone"
git clone --quiet --no-local --no-checkout "$repo" "$clone" || fail "git clone failed"
git -C "$clone" -c advice.detachedHead=false checkout --quiet --detach "$sha" || fail "git checkout $sha failed"
cd "$clone/site" || fail "$sha has no site/"
npm ci --ignore-scripts --no-audit --no-fund || fail "npm ci failed"
npm run build || fail "npm run build failed"
[ -f dist/index.html ] || fail "npm run build wrote no dist/index.html"
echo "$me: ok; a clone of $sha built with npm ci --ignore-scripts and npm run build in $clone/site"
