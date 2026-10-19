#!/bin/bash
# Reports, for each `conf.gem github:` line of build_config.rb, the commit
# that a build of this checkout clones today, and whether that commit moved
# since a previous report (docs/test/README.md, "Heads of the GitHub gems").
#
#   bash test/gem_heads.sh BUILD_CONFIG PREVIOUS REPORT [SUMMARY]
#
# BUILD_CONFIG is the build_config.rb to read. PREVIOUS is the report of an
# earlier run; when it is empty or the file does not exist, every gem is
# reported as "new". REPORT is the file that this run writes, in the same
# format as PREVIOUS. SUMMARY, when given, gets a Markdown table of the
# result appended (the workflow passes $GITHUB_STEP_SUMMARY).
#
# mruby clones a `github:` gem from https://github.com/<owner>/<repo>.git,
# at the branch named by the `branch:` option of the line, and at "master"
# when the line has none (mruby/lib/mruby/build/load_gems.rb). Without a
# lock file, which master does not commit, the build takes the head of that
# branch. This script reads that head with `git ls-remote`, and reads the
# repository's current name and whether it is archived with `gh api`
# (GH_TOKEN or a `gh auth login` is needed).
#
# The report is tab-separated, one gem per line:
#   repo, branch, head, default_branch, default_head, full_name, archived, lines
# Lines that start with "#" are comments.
#
# Exit status: 0 when every gem was read, also when gems moved; 1 when the
# head or the metadata of a gem could not be read; 2 on a usage error.
set -euo pipefail

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo "usage: bash test/gem_heads.sh BUILD_CONFIG PREVIOUS REPORT [SUMMARY]" >&2
  exit 2
fi
config=$1
previous=$2
report=$3
summary=${4:-}

if [ ! -f "${config}" ]; then
  echo "gem_heads: ${config} does not exist" >&2
  exit 2
fi

annotate() {
  # GitHub Actions turns these lines into annotations of the run. An
  # annotation ends at the end of its line, so newlines become spaces.
  local message=${2//$'\n'/ }
  if [ "${GITHUB_ACTIONS:-}" = true ]; then
    echo "::$1 title=gem heads::${message}"
  else
    echo "$1: ${message}"
  fi
}

# Every `conf.gem github: 'owner/repo'` line that is not a comment, also in
# the older `conf.gem :github => 'owner/repo'` form, with its line number
# and its `branch:` option, as "repo<TAB>branch<TAB>line".
gems=$(
  grep -n -E "^[[:space:]]*conf\.gem[[:space:]]+(github:|:github[[:space:]]*=>)" "${config}" |
  while IFS= read -r entry; do
    line=${entry%%:*}
    text=${entry#*:}
    repo=$(printf '%s\n' "${text}" | sed -n -E "s/.*github(:|[[:space:]]*=>)[[:space:]]*['\"]([^'\"]+)['\"].*/\2/p")
    branch=$(printf '%s\n' "${text}" | sed -n -E "s/.*branch(:|[[:space:]]*=>)[[:space:]]*['\"]([^'\"]+)['\"].*/\2/p")
    if [ -z "${repo}" ]; then
      echo "gem_heads: cannot read the repository of line ${line}: ${text}" >&2
      exit 1
    fi
    printf '%s\t%s\t%s\n' "${repo}" "${branch:-master}" "${line}"
  done
)
if [ -z "${gems}" ]; then
  echo "gem_heads: no conf.gem github: line in ${config}" >&2
  exit 1
fi

# One entry per repository and branch, with all of its line numbers.
gems=$(printf '%s\n' "${gems}" | awk -F '\t' '
  { key = $1 "\t" $2; if (!(key in lines)) { order[++n] = key; lines[key] = $3 } else { lines[key] = lines[key] "," $3 } }
  END { for (i = 1; i <= n; i++) print order[i] "\t" lines[order[i]] }')

prev_head() {
  # The head that the previous report recorded for repo $1 and branch $2.
  if [ -n "${previous}" ] && [ -f "${previous}" ]; then
    awk -F '\t' -v r="$1" -v b="$2" '!/^#/ && $1 == r && $2 == b { print $3; exit }' "${previous}"
  fi
}

tmp=$(mktemp)
trap 'rm -f "${tmp}"' EXIT
{
  printf '# gem heads of %s, %s\n' "${config}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '# repo\tbranch\thead\tdefault_branch\tdefault_head\tfull_name\tarchived\tlines\n'
} > "${tmp}"

# errors counts the gems that could not be read, not the failed commands.
errors=0
moved=0
count=0
rows=""
while IFS=$'\t' read -r repo branch lines; do
  count=$((count + 1))
  url="https://github.com/${repo}.git"
  head=""
  default_branch=""
  default_head=""
  full_name=""
  archived=""
  notes=()
  status=""

  if ! refs=$(git ls-remote --symref "${url}" HEAD "refs/heads/${branch}" 2>&1); then
    annotate error "${repo}: git ls-remote ${url} failed: ${refs}"
    status="error: the repository could not be read"
  else
    head=$(printf '%s\n' "${refs}" | awk -v ref="refs/heads/${branch}" '$1 != "ref:" && $2 == ref { print $1 }')
    default_branch=$(printf '%s\n' "${refs}" | awk '$1 == "ref:" && $3 == "HEAD" { sub("^refs/heads/", "", $2); print $2 }')
    default_head=$(printf '%s\n' "${refs}" | awk '$1 != "ref:" && $2 == "HEAD" { print $1 }')
    if [ -z "${head}" ]; then
      annotate error "${repo}: the branch ${branch}, which the build clones, does not exist (default branch: ${default_branch:-unknown})"
      status="error: no branch ${branch}"
    fi
  fi

  if meta=$(gh api "repos/${repo}" --jq '[.full_name, .default_branch, (.archived | tostring)] | @tsv' 2>&1); then
    IFS=$'\t' read -r full_name api_default archived <<< "${meta}"
    default_branch=${default_branch:-${api_default}}
  else
    annotate error "${repo}: gh api repos/${repo} failed: ${meta}"
    status=${status:-"error: the metadata could not be read"}
  fi
  case "${status}" in
    error:*) errors=$((errors + 1)) ;;
  esac

  if [ -n "${full_name}" ] && [ "$(printf '%s' "${full_name}" | tr '[:upper:]' '[:lower:]')" != "$(printf '%s' "${repo}" | tr '[:upper:]' '[:lower:]')" ]; then
    notes+=("renamed to ${full_name}; GitHub redirects the old name")
  fi
  if [ "${archived}" = true ]; then
    notes+=("archived")
  fi
  if [ -n "${default_branch}" ] && [ "${default_branch}" != "${branch}" ]; then
    notes+=("the default branch is ${default_branch} (head ${default_head:0:12}); the build clones ${branch}")
  fi

  if [ -z "${status}" ]; then
    old=$(prev_head "${repo}" "${branch}")
    if [ -z "${old}" ]; then
      status="new"
    elif [ "${old}" = "${head}" ]; then
      status="unchanged"
    else
      status="moved from ${old:0:12}: https://github.com/${repo}/compare/${old}...${head}"
      moved=$((moved + 1))
      annotate warning "${repo} ${branch} moved from ${old} to ${head}: https://github.com/${repo}/compare/${old}...${head}"
    fi
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "${repo}" "${branch}" "${head}" "${default_branch}" "${default_head}" "${full_name}" "${archived}" "${lines}" >> "${tmp}"
  note_text=""
  if [ "${#notes[@]}" -gt 0 ]; then
    note_text=$(printf '%s; ' "${notes[@]}")
    note_text=${note_text%; }
  fi
  echo "${repo} ${branch} ${head:-?} (lines ${lines}): ${status}${note_text:+ (${note_text})}"
  rows+="| [${repo}](https://github.com/${repo}) | ${lines} | ${branch} | \`${head:0:12}\` | ${status} | ${note_text} |"$'\n'
done <<< "${gems}"

mv "${tmp}" "${report}"
trap - EXIT

if [ -n "${previous}" ] && [ -f "${previous}" ]; then
  since="the previous report ($(sed -n '1s/^# gem heads of [^,]*, //p' "${previous}"))"
else
  since="no previous report, so every gem is new"
fi
echo "gems: ${count}, compared with ${since}, moved: ${moved}, errors: ${errors}"

if [ -n "${summary}" ]; then
  {
    echo "## Heads of the GitHub gems of ${config}"
    echo
    echo "Compared with ${since}. Moved: ${moved}. Errors: ${errors}."
    echo
    echo "| Gem | Lines | Branch the build clones | Head | Since the previous report | Notes |"
    echo "|---|---|---|---|---|---|"
    printf '%s' "${rows}"
  } >> "${summary}"
fi

if [ "${errors}" -gt 0 ]; then
  exit 1
fi
