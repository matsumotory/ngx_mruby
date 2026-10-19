#!/usr/bin/perl

# A test file of test/nginx-tests/self-test.sh. NT_SELF_TEST_BUILD (mruby or
# plain) picks its outcome; see the table in self-test.sh.

use strict;
use warnings;
use Test::More;
use POSIX ();

my $mruby = ($ENV{NT_SELF_TEST_BUILD} // "") eq "mruby";

ok(1, "first");
ok(!$mruby, "fails with mruby");
done_testing();
# Exit with 0 although a subtest failed: the summary entry has Wstat 0.
POSIX::_exit(0) if $mruby;
