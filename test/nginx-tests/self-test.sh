#!/bin/sh

# Checks results.pl and compare.pl on the made-up prove output in fixtures/,
# without nginx or the suite: every kind of result that results.pl tells
# apart (passed; skipped; failed subtests with and without a wait status; a
# wait status without failed subtests; TODO subtests that passed; a missing
# plan; a wrong plan), the three lists and the counts of compare.pl, and
# the stops of results.pl on a log that is not a complete run of prove. The
# nginx-tests job runs it before run.sh. It writes to
# NGINX_TESTS_OUT/self-test (default build_nginxtests/self-test).
#
#   sh test/nginx-tests/self-test.sh

set -e

HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${NGINX_TESTS_OUT:-build_nginxtests}/self-test
rm -rf "$OUT"
mkdir -p "$OUT/mruby" "$OUT/plain"

fail() {
    echo "self-test.sh: $1" >&2
    exit 1
}

for build in mruby plain; do
    cp "$HERE/fixtures/$build.prove.txt" "$OUT/$build/prove.log"
    echo "configure arguments: --with-debug" > "$OUT/$build/nginx-V.txt"
    perl "$HERE/results.pl" "$OUT/$build/prove.log" > "$OUT/$build/results.tsv"
done

tab=$(printf '\t')
cat > "$OUT/expected-mruby.tsv" <<END
a.t${tab}passed${tab}
b.t${tab}skipped${tab}no http_v2 available
c.t${tab}failed${tab}Failed test: 3; Non-zero exit status: 1
d.t${tab}passed${tab}TODO passed: 2
e.t${tab}failed${tab}Non-zero exit status: 255; Parse errors: No plan found in TAP output
f.t${tab}failed${tab}Parse errors: Bad plan. You planned 4 tests but ran 3.
g.t${tab}failed${tab}Failed test: 2
h.t${tab}failed${tab}Non-zero exit status: 2
END
diff "$OUT/expected-mruby.tsv" "$OUT/mruby/results.tsv" || fail "results.pl: unexpected results of fixtures/mruby.prove.txt"

perl "$HERE/compare.pl" "$OUT" 0000000 nginx-0.0.0 0000000 > "$OUT/compare.out"
[ "$(cat "$OUT/only-mruby.txt")" = "c.t
f.t
g.t
h.t" ] || fail "compare.pl: only-mruby.txt is not c.t, f.t, g.t and h.t"
[ "$(cat "$OUT/both.txt")" = "e.t" ] || fail "compare.pl: both.txt is not e.t"
[ "$(cat "$OUT/only-plain.txt")" = "a.t" ] || fail "compare.pl: only-plain.txt is not a.t"
grep -q '^| nginx with ngx_mruby | 8 | 2 | 5 | 1 | 29 |$' "$OUT/summary.md" || fail "compare.pl: wrong counts of the build with ngx_mruby"
grep -q '^| nginx without ngx_mruby | 8 | 5 | 2 | 1 | 29 |$' "$OUT/summary.md" || fail "compare.pl: wrong counts of the build without ngx_mruby"

# Logs that are not a complete run of prove: results.pl has to stop.
sed -n '1,3p' "$HERE/fixtures/mruby.prove.txt" > "$OUT/truncated.log"
sed 's/^Files=8,/Files=9,/' "$HERE/fixtures/mruby.prove.txt" > "$OUT/count.log"
grep -v '^Result:' "$HERE/fixtures/mruby.prove.txt" > "$OUT/no-result.log"
for log in truncated count no-result; do
    if perl "$HERE/results.pl" "$OUT/$log.log" > /dev/null 2>&1; then
        fail "results.pl accepted $log.log"
    fi
done

echo "self-test.sh: results.pl and compare.pl gave the expected results"
