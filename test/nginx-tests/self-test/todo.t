#!/usr/bin/perl

# A test file of test/nginx-tests/self-test.sh. NT_SELF_TEST_BUILD (mruby or
# plain) picks its outcome; see the table in self-test.sh.

use strict;
use warnings;
use Test::More;
use POSIX ();

my $mruby = ($ENV{NT_SELF_TEST_BUILD} // "") eq "mruby";

plan(tests => 3);
ok(1, "first");
TODO: {
	local $TODO = "not yet";
	ok(1, "a TODO subtest that passes");
	ok(1, "another one");
}
