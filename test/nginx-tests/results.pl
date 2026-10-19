#!/usr/bin/perl

# Reads the output of prove (test/nginx-tests/run.sh) and prints one line per
# test file, separated by tabs: the file (without the "./" that prove
# prints before it), its result (passed, failed or
# skipped) and a detail (the reason of a skip, the failed subtests, or the
# number of TODO subtests that passed). Exits non-zero when the log is not a
# complete run of prove: no "Files=" or "Result:" line, or a number of files
# that differs from the count in the "Files=" line.
#
# prove prints a line for each file ("access.t .. ok", "h2.t .. skipped:
# no http_v2 available", "foo.t .. Failed 1/12 subtests"), and after all of
# them a "Test Summary Report" with an entry for each file that failed or
# had TODO subtests that passed:
#
#   foo.t (Wstat: 256 (exited 1) Tests: 12 Failed: 1)
#     Failed test:  3
#     Non-zero exit status: 1
#
# A file fails when its entry has failed subtests, a wait status other than
# 0 or parse errors (a missing or wrong plan); an entry with TODO subtests
# that passed and nothing else is a file that passed.

use strict;
use warnings;

my $log = shift or die "usage: results.pl prove.log\n";
open my $fh, '<', $log or die "results.pl: cannot open $log: $!\n";

my (%result, %detail, @order, %summary, $files, $result_line);
my ($in_summary, $entry);

while (my $line = <$fh>) {
	chomp $line;

	if ($line =~ /^Test Summary Report$/) {
		$in_summary = 1;
		next;
	}
	if ($line =~ /^Files=(\d+), Tests=(\d+)/) {
		$files = $1;
		$in_summary = 0;
		next;
	}
	if ($line =~ /^Result: (\S+)/) {
		$result_line = $1;
		next;
	}

	if ($in_summary) {
		next if $line =~ /^-+$/;
		if ($line =~ /^(\S+\.t) \(Wstat: (\d+).*?Tests: (\d+) Failed: (\d+)\)$/) {
			my ($file, $wstat, $tests, $failed) = ($1, $2, $3, $4);
			($entry = $file) =~ s{^\./}{};
			$summary{$entry} = { wstat => $wstat, tests => $tests,
				failed => $failed, lines => [] };
			next;
		}
		if (defined $entry && $line =~ /^\s+(\S.*)$/) {
			push @{$summary{$entry}{lines}}, $1;
		}
		next;
	}

	# The line of a file: its name, dots and the result. Diagnostics of the
	# test files ("#   Failed test ...") and nginx's messages on stderr
	# come between these lines and do not start with a name of a test file.
	if ($line =~ /^(\S+\.t) \.+ (.*)$/) {
		my ($file, $text) = ($1, $2);
		$file =~ s{^\./}{};
		next if exists $result{$file};
		push @order, $file;
		if ($text =~ /^skipped: (.*)$/) {
			$result{$file} = 'skipped';
			$detail{$file} = $1;
		} else {
			$result{$file} = 'passed';
			$detail{$file} = '';
		}
	}
}
close $fh;

die "results.pl: $log has no \"Files=\" line of prove\n" unless defined $files;
die "results.pl: $log has no \"Result:\" line of prove\n"
	unless defined $result_line;
die "results.pl: $log has " . scalar(@order) . " result lines of test files,"
	. " and prove counted $files files\n" if @order != $files;

for my $file (sort keys %summary) {
	die "results.pl: $file is in the Test Summary Report of $log"
		. " but has no result line\n" unless exists $result{$file};

	my $s = $summary{$file};
	my $parse_errors = grep { /^Parse errors:/ } @{$s->{lines}};
	if ($s->{failed} > 0 || $s->{wstat} != 0 || $parse_errors) {
		$result{$file} = 'failed';
		$detail{$file} = join '; ', @{$s->{lines}};
	} else {
		$detail{$file} = join '; ', @{$s->{lines}};
	}
}

for my $file (sort @order) {
	(my $d = $detail{$file}) =~ s/\s+/ /g;
	print "$file\t$result{$file}\t$d\n";
}
