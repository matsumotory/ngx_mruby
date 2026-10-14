#!/bin/sh
# Fails when a change adds a file that does not belong in the repository
# (docs/test/README.md, "In CI").
#
#   sh test/check_added_files.sh BASE HEAD
#
# BASE and HEAD are commits (or trees) of the git repository in the current
# directory. The added files are the paths that HEAD has and BASE does not
# have (git diff --no-renames --diff-filter=A), so a file that is renamed or
# moved counts as added at its new path. An added file fails when
#
#   - the last line of forbidden_paths.txt (next to this script) that its
#     path matches is a pattern, not an exception (a line starting with "!"),
#   - or it is empty (0 bytes) and its name is not .gitkeep or .keep.
#
# Exit status: 0 when every added file passes (the number of checked files
# is printed), 1 when one fails (each failing path is printed with the
# pattern that matched it, or "empty file"), 2 on a usage error, a missing
# pattern file, an invalid pattern or a failed git command.
#
# The script reads the pattern file and the git repository, and writes
# nothing.

set -u
set -f

me=check_added_files.sh
pattern_file=$(dirname "$0")/forbidden_paths.txt
tab=$(printf '\t')

usage() {
  echo "usage: sh test/check_added_files.sh BASE HEAD" >&2
  exit 2
}

[ "$#" -eq 2 ] || usage
base=$1
head=$2
for rev in "$base" "$head"; do
  case $rev in
    '' | -*) usage ;;
  esac
  if ! git rev-parse --verify --quiet "$rev^{tree}" >/dev/null; then
    echo "$me: $rev is not a commit or tree of this repository" >&2
    exit 2
  fi
done

if [ ! -f "$pattern_file" ] || [ ! -r "$pattern_file" ]; then
  echo "$me: pattern file $pattern_file is missing" >&2
  exit 2
fi

empty_blob=$(printf '' | git hash-object -t blob --stdin) || exit 2

# The options keep the user's git configuration from changing the output:
# paths from the top of the repository, UTF-8 left unquoted, no rename
# detection.
raw=$(git -c core.quotePath=false diff --raw --no-abbrev --no-renames \
  --no-relative --no-ext-diff --no-color --diff-filter=A "$base" "$head" --) || {
  echo "$me: git diff $base $head failed" >&2
  exit 2
}

# One line per added file: ":000000 <mode> <zero id> <blob id> A<TAB><path>".
# git quotes a path that holds a control character, a double quote or a
# backslash; such a path is matched without the surrounding quotes.
count=0
names=
while IFS= read -r line; do
  [ -n "$line" ] || continue
  meta=${line%%"$tab"*}
  path=${line#*"$tab"}
  set -- $meta
  mode=$2
  blob=$4
  case $path in
    \"*\") name=${path#\"}; name=${name%\"} ;;
    *) name=$path ;;
  esac
  count=$((count + 1))
  eval "path_$count=\$path"
  names="$names$name
"
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
done <<RAW
$raw
RAW

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
i=0
while [ "$i" -lt "$count" ]; do
  i=$((i + 1))
  eval "path=\$path_$i; decided=\${decided_$i:-}; empty=\${empty_$i:-}"
  if [ -n "$decided" ]; then
    eval "kind=\$kind_$decided; pat=\$pat_$decided; line=\$line_$decided"
    if [ "$kind" = pattern ]; then
      echo "$path: matches the forbidden pattern '$pat' ($pattern_file:$line)"
      failed=$((failed + 1))
    fi
  fi
  if [ -n "$empty" ]; then
    echo "$path: empty file (0 bytes)"
    failed=$((failed + 1))
  fi
done

if [ "$failed" -ne 0 ]; then
  echo "$me: $failed problem(s) in the $count file(s) added between $base and $head."
  echo "Remove these files from the change. If one belongs in the repository, change"
  echo "$pattern_file (or, for an empty file, this script) in the same change and say why."
  exit 1
fi
echo "$me: $count added file(s) checked between $base and $head, none forbidden or empty"
