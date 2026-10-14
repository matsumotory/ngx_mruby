#!/bin/sh
# Fails when a change adds a file that does not belong in the repository
# (docs/test/README.md, "Files that do not belong in the repository").
#
#   sh test/check_added_files.sh BASE HEAD [TIP]
#
# BASE and HEAD are commits (or trees) of the git repository in the current
# directory, and TIP is a commit. Two lists of files are checked:
#
#   - The files that the change adds: the paths that HEAD has and BASE does
#     not have (git diff --no-renames --diff-filter=A), so a file that is
#     renamed or moved counts as added at its new path.
#   - The files that its commits add: each commit from TIP back along first
#     parents to BASE (git log --first-parent BASE..TIP), compared with its
#     first parent. A file that one commit adds and a later one removes stays
#     in the history, so it is checked as well. TIP is HEAD when it is not
#     given; this list is left out when BASE or HEAD is a tree and TIP is not
#     given. It needs the whole history: the script exits 2 in a shallow
#     clone.
#
# A file of either list fails when the last line of forbidden_paths.txt
# (next to this script) that its path matches is a pattern, not an exception
# (a line starting with "!"). A file of the first list also fails when it is
# empty (0 bytes) and its name is not .gitkeep or .keep.
#
# Exit status: 0 when every file passes (the number of checked files is
# printed), 1 when one fails (each failing path is printed with the pattern
# that matched it, or "empty file", and with the commit that added it when a
# commit of the second list did), 2 on a usage error, a missing pattern
# file, an invalid pattern, a shallow clone or a failed git command.
#
# The script reads the pattern file and the git repository, and writes
# nothing.

set -u
set -f

me=check_added_files.sh
pattern_file=$(dirname "$0")/forbidden_paths.txt
tab=$(printf '\t')

usage() {
  echo "usage: sh test/check_added_files.sh BASE HEAD [TIP]" >&2
  exit 2
}

is_commit() {
  git rev-parse --verify --quiet "$1^{commit}" >/dev/null 2>&1
}

[ "$#" -eq 2 ] || [ "$#" -eq 3 ] || usage
base=$1
head=$2
tip=${3-}
for rev in "$@"; do
  case $rev in
    '' | -*) usage ;;
  esac
  if ! git rev-parse --verify --quiet "$rev^{tree}" >/dev/null; then
    echo "$me: $rev is not a commit or tree of this repository" >&2
    exit 2
  fi
done

if [ -n "$tip" ]; then
  for rev in "$base" "$tip"; do
    if ! is_commit "$rev"; then
      echo "$me: $rev is not a commit, so the commits of $base..$tip cannot be listed" >&2
      exit 2
    fi
  done
elif is_commit "$base" && is_commit "$head"; then
  tip=$head
fi

if [ -n "$tip" ]; then
  # A shallow clone ends the history at its boundary, so git cannot tell
  # which commits BASE already has, or which commits lie beyond it.
  shallow=$(git rev-parse --is-shallow-repository) || exit 2
  if [ "$shallow" != false ]; then
    echo "$me: the repository is a shallow clone, so the commits of $base..$tip cannot be listed;" >&2
    echo "fetch the whole history (git fetch --unshallow) and run the check again" >&2
    exit 2
  fi
fi

if [ ! -f "$pattern_file" ] || [ ! -r "$pattern_file" ]; then
  echo "$me: pattern file $pattern_file is missing" >&2
  exit 2
fi

empty_blob=$(printf '' | git hash-object -t blob --stdin) || exit 2

# The options keep the user's git configuration from changing the output:
# paths from the top of the repository, UTF-8 left unquoted, no rename
# detection, submodule entries (gitlinks) listed whatever the configuration
# or .gitmodules says, no external diff, color or signature lines.
raw=$(git -c core.quotePath=false diff --raw --no-abbrev --no-renames \
  --no-relative --no-ext-diff --no-color --ignore-submodules=none \
  --diff-filter=A "$base" "$head" --) || {
  echo "$me: git diff $base $head failed" >&2
  exit 2
}

# The commits follow first parents only: a merge commit is compared with its
# first parent, so the files that it brings in from its second parent are
# checked with the paths they have in the repository. (The second parent of
# a subtree merge, ./update-mruby-subtree, holds the paths of mruby/ without
# the prefix.)
ncommits=0
log=
if [ -n "$tip" ]; then
  ncommits=$(git rev-list --first-parent --count "$base..$tip") || {
    echo "$me: git rev-list $base..$tip failed" >&2
    exit 2
  }
  log=$(git -c core.quotePath=false log --first-parent \
    --diff-merges=first-parent --reverse --root --format='commit %H' \
    --raw --no-abbrev --no-renames --no-relative --no-ext-diff --no-color \
    --no-show-signature --ignore-submodules=none --diff-filter=A \
    "$base..$tip" --) || {
    echo "$me: git log $base..$tip failed" >&2
    exit 2
  }
fi

# git prints one line per added file: ":000000 <mode> <zero id> <blob id>
# A<TAB><path>". The files that the change adds come first, then the files
# that only its commits add, each path once. Each line of the list is
# "<mode> <blob id> <1 when the change adds it, else 0> <the oldest commit
# that adds it, or -><TAB><path>".
list=$({
  printf '%s\n' "$raw"
  printf '%s\n' "$log"
} | LC_ALL=C awk -F "$tab" '
  /^commit / { c = substr($0, 8); next }
  /^:/ {
    p = substr($0, length($1) + 2)
    if (!(p in seen)) {
      split($1, m, " ")
      seen[p] = ++n; path[n] = p; mode[n] = m[2]; blob[n] = m[4]
      added[n] = (c == "") ? 1 : 0; by[n] = "-"
    }
    if (c != "" && by[seen[p]] == "-") by[seen[p]] = c
  }
  END {
    for (i = 1; i <= n; i++)
      printf "%s %s %s %s\t%s\n", mode[i], blob[i], added[i], by[i], path[i]
  }') || {
  echo "$me: awk failed" >&2
  exit 2
}

# git quotes a path that holds a control character, a double quote or a
# backslash; such a path is matched without the surrounding quotes.
count=0
names=
while IFS= read -r line; do
  [ -n "$line" ] || continue
  meta=${line%%"$tab"*}
  path=${line#*"$tab"}
  set -- $meta
  mode=$1
  blob=$2
  added=$3
  by=$4
  case $path in
    \"*\") name=${path#\"}; name=${name%\"} ;;
    *) name=$path ;;
  esac
  count=$((count + 1))
  eval "path_$count=\$path; added_$count=\$added; by_$count=\$by"
  names="$names$name
"
  if [ "$added" = 1 ]; then
    case $mode in
      100*)
        if [ "$blob" = "$empty_blob" ]; then
          case ${name##*/} in
            .gitkeep | .keep) ;;
            *) eval "empty_$count=1" ;;
          esac
        fi
        ;;
    esac
  fi
done <<LIST
$list
LIST

# Each line of the pattern file, in order, becomes the deciding line of the
# paths it matches: decided_<n> holds the number of the last line that the
# n-th path matched.
lineno=0
npat=0
while read -r pat || [ -n "$pat" ]; do
  lineno=$((lineno + 1))
  case $pat in
    '' | '#'*) continue ;;
  esac
  npat=$((npat + 1))
  case $pat in
    '!'*) kind=exception; re=${pat#!} ;;
    *) kind=pattern; re=$pat ;;
  esac
  if [ -z "$re" ]; then
    echo "$me: $pattern_file:$lineno: empty exception" >&2
    exit 2
  fi
  eval "kind_$npat=\$kind; pat_$npat=\$pat; line_$npat=\$lineno"
  # grep compiles the expression even when no file was added, so an invalid
  # pattern fails every run. -a and LC_ALL=C keep a path that is not valid
  # UTF-8 from turning the output into "Binary file matches".
  hits=$(printf '%s' "$names" | LC_ALL=C grep -a -n -E -e "$re")
  case $? in
    0 | 1) ;;
    *)
      echo "$me: $pattern_file:$lineno: invalid pattern: $pat" >&2
      exit 2
      ;;
  esac
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    n=${hit%%:*}
    case $n in
      '' | *[!0-9]*)
        echo "$me: unexpected output of grep: $hit" >&2
        exit 2
        ;;
    esac
    eval "decided_$n=\$npat"
  done <<HITS
$hits
HITS
done <"$pattern_file"

if [ "$npat" -eq 0 ]; then
  echo "$me: pattern file $pattern_file has no pattern" >&2
  exit 2
fi

failed=0
in_history=0
i=0
while [ "$i" -lt "$count" ]; do
  i=$((i + 1))
  eval "path=\$path_$i; added=\$added_$i; by=\$by_$i"
  eval "decided=\${decided_$i:-}; empty=\${empty_$i:-}"
  if [ "$by" = - ]; then
    from=
  else
    from=", added by commit $by"
  fi
  if [ -n "$decided" ]; then
    eval "kind=\$kind_$decided; pat=\$pat_$decided; line=\$line_$decided"
    if [ "$kind" = pattern ]; then
      echo "$path: matches the forbidden pattern '$pat' ($pattern_file:$line)$from"
      failed=$((failed + 1))
      [ "$added" = 1 ] || in_history=$((in_history + 1))
    fi
  fi
  if [ -n "$empty" ]; then
    echo "$path: empty file (0 bytes)"
    failed=$((failed + 1))
  fi
done

if [ -n "$tip" ]; then
  scope="between $base and $head and in the $ncommits commit(s) of $base..$tip"
else
  scope="between $base and $head"
fi
if [ "$failed" -ne 0 ]; then
  echo "$me: $failed problem(s) in the $count file(s) added $scope."
  echo "Remove these files from the change. If one belongs in the repository, change"
  echo "$pattern_file (or, for an empty file, this script) in the same change and say why."
  if [ "$in_history" -ne 0 ]; then
    echo "A file that a commit adds stays in the history after a later commit removes it:"
    echo "remove it from the commit that added it, or squash the commits."
  fi
  exit 1
fi
echo "$me: $count added file(s) checked $scope, none forbidden or empty"
