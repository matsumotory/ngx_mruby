#!/usr/bin/perl

# Compares the results of nginx-tests on nginx with ngx_mruby (OUT/mruby)
# and on nginx without it (OUT/plain), as test/nginx-tests/run.sh wrote them
# (results.tsv of results.pl, nginx-V.txt, prove.log), and writes:
#
#   OUT/summary.md       the counts of both builds and the lists below, for
#                        the job summary
#   OUT/only-mruby.txt   files that fail with ngx_mruby and not without it
#   OUT/both.txt         files that fail on both builds
#   OUT/only-plain.txt   files that fail without ngx_mruby and not with it
#
# In GitHub Actions (GITHUB_ACTIONS=true) it also prints a warning annotation
# for each file of only-mruby.txt. Exits non-zero when a result file is missing or
# the two builds ran different sets of files.

use strict;
use warnings;

my ($out, $suite_commit, $nginx_ver, $head) = @ARGV;
die "usage: compare.pl OUT NGINX_TESTS_COMMIT NGINX_SRC_VER NGX_MRUBY_COMMIT\n"
	unless defined $head;

my %r;
for my $build (qw/mruby plain/) {
	my $tsv = "$out/$build/results.tsv";
	open my $fh, '<', $tsv or die "compare.pl: cannot open $tsv: $!\n";
	while (<$fh>) {
		chomp;
		my ($file, $result, $detail) = split /\t/, $_, 3;
		$r{$build}{$file} = { result => $result, detail => $detail // '' };
	}
	close $fh;
	die "compare.pl: $tsv is empty\n" unless %{$r{$build} || {}};
}

my @files = sort keys %{$r{mruby}};
my @plain_files = sort keys %{$r{plain}};
die "compare.pl: the builds ran different test files\n"
	if "@files" ne "@plain_files";

sub count {
	my ($build, $result) = @_;
	return scalar grep { $r{$build}{$_}{result} eq $result } @files;
}

sub subtests {
	my ($build) = @_;
	open my $fh, '<', "$out/$build/prove.log" or return '?';
	while (<$fh>) {
		return $1 if /^Files=\d+, Tests=(\d+)/;
	}
	return '?';
}

sub configure_args {
	my ($build) = @_;
	open my $fh, '<', "$out/$build/nginx-V.txt" or return '?';
	while (<$fh>) {
		return $1 if /^configure arguments: (.*)$/;
	}
	return '?';
}

my (@only_mruby, @both, @only_plain, @skip_diff);
for my $file (@files) {
	my $m = $r{mruby}{$file}{result};
	my $p = $r{plain}{$file}{result};
	push @only_mruby, $file if $m eq 'failed' && $p ne 'failed';
	push @both, $file if $m eq 'failed' && $p eq 'failed';
	push @only_plain, $file if $m ne 'failed' && $p eq 'failed';
	push @skip_diff, $file
		if ($m eq 'skipped') != ($p eq 'skipped');
}

sub write_list {
	my ($name, @list) = @_;
	open my $fh, '>', "$out/$name" or die "compare.pl: $out/$name: $!\n";
	print $fh "$_\n" for @list;
	close $fh;
}
write_list('only-mruby.txt', @only_mruby);
write_list('both.txt', @both);
write_list('only-plain.txt', @only_plain);

chomp(my $date = `date -u '+%Y-%m-%d %H:%M UTC'`);
chomp(my $machine = `uname -sm`);

my $md = '';
$md .= "## nginx-tests\n\n";
$md .= "nginx-tests `$suite_commit` on $nginx_ver, ngx_mruby `$head`,"
	. " $machine, $date.\n\n";
$md .= "| Build | Test files | Passed | Failed | Skipped | Subtests run |\n";
$md .= "|---|---|---|---|---|---|\n";
for my $build (qw/mruby plain/) {
	my $name = $build eq 'mruby' ? 'nginx with ngx_mruby' : 'nginx without ngx_mruby';
	$md .= "| $name | " . scalar(@files) . " | " . count($build, 'passed')
		. " | " . count($build, 'failed') . " | " . count($build, 'skipped')
		. " | " . subtests($build) . " |\n";
}
$md .= "\n";

sub list_md {
	my ($title, @list) = @_;
	my $s = "### $title: " . scalar(@list) . "\n\n";
	return $s . "none\n\n" unless @list;
	for my $file (@list) {
		my $m = $r{mruby}{$file};
		my $p = $r{plain}{$file};
		$s .= "- `$file`: with ngx_mruby $m->{result}"
			. ($m->{detail} ne '' ? " ($m->{detail})" : '')
			. "; without $p->{result}"
			. ($p->{detail} ne '' ? " ($p->{detail})" : '') . "\n";
	}
	return "$s\n";
}
$md .= list_md('Failed with ngx_mruby only', @only_mruby);
$md .= list_md('Failed on both builds', @both);
$md .= list_md('Failed without ngx_mruby only', @only_plain);
$md .= list_md('Skipped on one build only', @skip_diff) if @skip_diff;

# The reasons of the skips, as the test files print them; a file is skipped
# when nginx lacks a module that it needs, or the machine a perl module or a
# program (the counts are those of the build with ngx_mruby).
my %reasons;
$reasons{$r{mruby}{$_}{detail}}++
	for grep { $r{mruby}{$_}{result} eq 'skipped' } @files;
if (%reasons) {
	$md .= "### Reasons of the skips with ngx_mruby\n\n";
	$md .= join(', ', map { "$_ ($reasons{$_})" }
		sort { $reasons{$b} <=> $reasons{$a} || $a cmp $b } keys %reasons)
		. "\n\n";
}

$md .= "Configure arguments with ngx_mruby: `" . configure_args('mruby') . "`\n\n";
$md .= "Configure arguments without: `" . configure_args('plain') . "`\n";

open my $fh, '>', "$out/summary.md" or die "compare.pl: $out/summary.md: $!\n";
print $fh $md;
close $fh;
print $md;

if (($ENV{GITHUB_ACTIONS} // '') eq 'true') {
	for my $file (@only_mruby) {
		print "::warning title=nginx-tests::$file fails on nginx with"
			. " ngx_mruby and not on nginx without it (see the job summary"
			. " and the artifact nginx-tests)\n";
	}
}
