#!/bin/sh

# Checks results.pl and compare.pl on real output of prove, without nginx
# or the suite. The test files in self-test/ read NT_SELF_TEST_BUILD and
# end, for each of the two builds, as this table says; prove runs them in
# parallel, as run.sh runs nginx-tests:
#
#   file                                  mruby                  plain
#   pass.t                                passes                 fails
#   skip.t                                skipped                skipped
#   skip_mruby.t                          skipped                passes
#   fail.t                                subtest 3 fails        passes
#   todo.t                                passes, 2 TODO pass    the same
#   noplan.t                              dies before its plan   the same
#   badplan.t                             runs 3 of 4, exits 0   passes
#   failed_with_exit_0_and_a_long_name.t  fails, exits with 0    passes
#   exit2.t                               passes, exits with 2   passes
#
# The long name makes prove pad the other names of its Test Summary Report.
# The check covers the results of results.pl, the lists and the counts of
# compare.pl, and the stops of results.pl on a log that is not a complete
# run of prove. The nginx-tests job runs it before run.sh. It writes to
# NGINX_TESTS_OUT/self-test (default build_nginxtests/self-test).
#
#   sh test/nginx-tests/self-test.sh

set -e

HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${NGINX_TESTS_OUT:-build_nginxtests}/self-test
case "$OUT" in /*) ;; *) OUT="$(pwd)/$OUT" ;; esac
rm -rf "$OUT"
mkdir -p "$OUT/mruby" "$OUT/plain"

fail() {
    echo "self-test.sh: $1" >&2
    exit 1
}

for build in mruby plain; do
    # prove exits with 1 here: test files fail on purpose.
    (cd "$HERE/self-test" && NT_SELF_TEST_BUILD=$build prove -j 2 .) > "$OUT/$build/prove.log" 2>&1 || true
    echo "configure arguments: --with-debug" > "$OUT/$build/nginx-V.txt"
    perl "$HERE/results.pl" "$OUT/$build/prove.log" > "$OUT/$build/results.tsv"
done

check_results() {
    build=$1
    expected=$2
    actual=$(cut -f 1,2 "$OUT/$build/results.tsv" | tr '\t' ' ')
    [ "$actual" = "$expected" ] || {
        printf 'expected:\n%s\nresults.tsv:\n%s\n' "$expected" "$actual" >&2
        fail "results.pl: unexpected results of the build $build (see $OUT/$build/prove.log)"
    }
}
check_results mruby "badplan.t failed
exit2.t failed
fail.t failed
failed_with_exit_0_and_a_long_name.t failed
noplan.t failed
pass.t passed
skip.t skipped
skip_mruby.t skipped
todo.t passed"
check_results plain "badplan.t passed
exit2.t passed
fail.t passed
failed_with_exit_0_and_a_long_name.t passed
noplan.t failed
pass.t failed
skip.t skipped
skip_mruby.t passed
todo.t passed"
grep -q "^skip.t	skipped	no http_v2 available$" "$OUT/mruby/results.tsv" || fail "results.pl: the reason of the skip of skip.t is missing"
grep -q "^todo.t	passed	TODO passed: " "$OUT/mruby/results.tsv" || fail "results.pl: the TODO subtests of todo.t are missing"

perl "$HERE/compare.pl" "$OUT" 0000000 nginx-0.0.0 0000000 > "$OUT/compare.out"
[ "$(cat "$OUT/only-mruby.txt")" = "badplan.t
exit2.t
fail.t
failed_with_exit_0_and_a_long_name.t" ] || fail "compare.pl: only-mruby.txt is not badplan.t, exit2.t, fail.t and failed_with_exit_0_and_a_long_name.t"
[ "$(cat "$OUT/both.txt")" = "noplan.t" ] || fail "compare.pl: both.txt is not noplan.t"
[ "$(cat "$OUT/only-plain.txt")" = "pass.t" ] || fail "compare.pl: only-plain.txt is not pass.t"
grep -q '^| nginx with ngx_mruby | 9 | 2 | 5 | 2 | [0-9][0-9]* |$' "$OUT/summary.md" || fail "compare.pl: wrong counts of the build with ngx_mruby"
grep -q '^| nginx without ngx_mruby | 9 | 6 | 2 | 1 | [0-9][0-9]* |$' "$OUT/summary.md" || fail "compare.pl: wrong counts of the build without ngx_mruby"
grep -q '^### Skipped on one build only: 1$' "$OUT/summary.md" || fail "compare.pl: the list of files skipped on one build only is missing"
grep -q '^- `skip_mruby.t`: with ngx_mruby skipped' "$OUT/summary.md" || fail "compare.pl: skip_mruby.t is not in the list of files skipped on one build only"

# Logs that are not a complete run of prove: results.pl has to stop.
files=$(sed -n 's/^Files=\([0-9]*\),.*/\1/p' "$OUT/mruby/prove.log")
sed -n '1,3p' "$OUT/mruby/prove.log" > "$OUT/truncated.log"
sed "s/^Files=$files,/Files=$((files + 1)),/" "$OUT/mruby/prove.log" > "$OUT/count.log"
grep -v '^Result:' "$OUT/mruby/prove.log" > "$OUT/no-result.log"
for log in truncated count no-result; do
    if perl "$HERE/results.pl" "$OUT/$log.log" > /dev/null 2>&1; then
        fail "results.pl accepted $log.log"
    fi
done

echo "self-test.sh: results.pl and compare.pl gave the expected results"
