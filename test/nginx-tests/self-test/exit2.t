#!/usr/bin/perl

# A test file of test/nginx-tests/self-test.sh. NT_SELF_TEST_BUILD (mruby or
# plain) picks its outcome; see the table in self-test.sh.

use strict;
use warnings;
use Test::More;
use POSIX ();

my $mruby = ($ENV{NT_SELF_TEST_BUILD} // "") eq "mruby";

ok(1, "subtest $_") for 1 .. 5;
done_testing();
# Every subtest passed, but the file exits with 2.
POSIX::_exit(2) if $mruby;
