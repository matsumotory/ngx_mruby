#!/usr/bin/perl

# A test file of test/nginx-tests/self-test.sh. NT_SELF_TEST_BUILD (mruby or
# plain) picks its outcome; see the table in self-test.sh.

use strict;
use warnings;
use Test::More;
use POSIX ();

my $mruby = ($ENV{NT_SELF_TEST_BUILD} // "") eq "mruby";

plan(tests => 4);
ok(1, "subtest $_") for 1 .. ($mruby ? 3 : 4);
# Exit with 0, so that only the parse error (the wrong plan) marks the file.
POSIX::_exit(0) if $mruby;
