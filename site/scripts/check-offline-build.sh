#!/bin/sh
# Check of step 2 (docs/proposals/site.md, 4.4 and section 6): the site
# builds with network access blocked after npm ci, so that the build fetches
# no font, script or other file.
#
#   sh site/scripts/check-offline-build.sh [SITE_DIR]
#
# SITE_DIR (default: the site/ directory of this script) must hold
# node_modules from `npm ci --ignore-scripts`. The build runs without
# network: on Linux in a network namespace of its own (`sudo unshare --net`,
# then back to the calling user), on macOS under sandbox-exec with
# `(deny network*)`. Before the build, the script checks inside the same
# sandbox that a request to registry.npmjs.org fails, so that a sandbox that
# lets the network through does not pass. It exits 1 on a failure.
set -eu

here=$(cd "$(dirname "$0")/.." && pwd)
site=$(cd "${1:-$here}" && pwd)
[ -d "$site/node_modules" ] || { echo "check-offline-build.sh: $site has no node_modules: run npm ci --ignore-scripts first"; exit 1; }

offline() {
  case "$(uname -s)" in
    Linux)
      # sudo starts with an empty environment: pass on the star count of
      # the header that site.yml read (4.10), empty when it has none.
      sudo -n unshare --net -- sudo -n -u "$(id -un)" env "PATH=$PATH" "HOME=$HOME" ASTRO_TELEMETRY_DISABLED=1 \
        "NGX_MRUBY_SITE_STARS=${NGX_MRUBY_SITE_STARS-}" "NGX_MRUBY_SITE_STARS_DATE=${NGX_MRUBY_SITE_STARS_DATE-}" sh -c "cd '$site' && $1"
      ;;
    Darwin)
      sandbox-exec -p '(version 1)(allow default)(deny network*)' sh -c "cd '$site' && $1"
      ;;
    *)
      echo "check-offline-build.sh: no way to block the network on $(uname -s)"
      exit 1
      ;;
  esac
}

# The network must be blocked: a request that succeeds exits 0, a refused one 3.
if offline "node -e \"fetch('https://registry.npmjs.org/').then(() => process.exit(0), () => process.exit(3))\""; then
  echo "check-offline-build.sh: a request to registry.npmjs.org succeeded inside the sandbox, so the network is not blocked"
  exit 1
else
  status=$?
  if [ "$status" -ne 3 ]; then
    echo "check-offline-build.sh: the probe of the network exited $status, not 3"
    exit 1
  fi
fi

rm -rf "$site/dist"
if ! offline "npm run build > '$site/offline-build.log' 2>&1"; then
  tail -n 30 "$site/offline-build.log"
  echo "check-offline-build.sh: npm run build failed with network access blocked (log: $site/offline-build.log)"
  exit 1
fi
[ -f "$site/dist/index.html" ] || { echo "check-offline-build.sh: the build left no dist/index.html"; exit 1; }
pages=$(find "$site/dist" -name '*.html' | wc -l | tr -d ' ')
echo "check-offline-build.sh: ok; npm run build in $site built $pages HTML files with network access blocked (a request to registry.npmjs.org failed in the same sandbox)"
