#!/usr/bin/env ruby
# Copies the files of the test suite into a directory of the build and moves
# every port of the suite by an offset. test.sh runs this file with CRuby,
# like the other helpers in this directory, before it installs the
# configuration, and then reads the configuration, the hook scripts and the
# tests from the copy, so that two checkouts can run test.sh at the same time
# on one machine with different offsets (TEST_SH_PORT_OFFSET).
#
# Usage:
#   ruby test/t/cases/_stage.rb OFFSET DEST
#
# It copies test/t, test/conf and test/html, and the two files of test/soak
# that test/t/cases/_agent_proxy_client.rb loads (mock_llm.rb and
# http_client.rb), to DEST/test/ at the same relative paths, after it has
# removed DEST/test. Files keep their mode, so test/t/issue-268-test.rb stays
# executable.
#
# The ports of the suite are the numbers from 12345 to 12399 and from 18080
# to 18199 (see "Ports" in docs/test/README.md). In every text file, each
# such number written as five digits with no digit or letter next to it
# becomes the number plus OFFSET. Files with a NUL byte (images) are copied
# as they are. With OFFSET 0 the copy is the same as the source. The script
# fails, with the file and the line, when such a number is written with an
# underscore between its digits, which the rule would not see, and when
# OFFSET moves a port out of 10000 to 65535: the ports stay five digits
# long, as the one number of the ranges that is not a port expects (see
# "Ports" in docs/test/README.md).
#
# It prints one line with the number of files and of numbers moved, and
# exits 0, or 1 with the reason.

require 'fileutils'

RANGES = [12345..12399, 18080..18199].freeze
SOURCES = ['test/t', 'test/conf', 'test/html', 'test/soak/mock_llm.rb', 'test/soak/http_client.rb'].freeze
NUMBER = /(?<![0-9A-Za-z_])([0-9]{5})(?![0-9A-Za-z_])/.freeze
UNDERSCORED = /(?<![0-9A-Za-z_])([0-9]{2})_([0-9]{3})(?![0-9A-Za-z_])/.freeze

def finish(status, message)
  puts "stage: #{message}"
  exit status
end

def port?(number)
  RANGES.any? { |range| range.cover?(number) }
end

offset_text, dest = ARGV
finish(1, 'usage: ruby test/t/cases/_stage.rb OFFSET DEST') unless offset_text && dest
finish(1, "TEST_SH_PORT_OFFSET must be an integer, not #{offset_text.inspect}") unless offset_text =~ /\A-?[0-9]+\z/
offset = Integer(offset_text, 10)
RANGES.each do |range|
  low = range.first + offset
  high = range.last + offset
  next if low >= 10000 && high <= 65535

  finish(1, "TEST_SH_PORT_OFFSET #{offset} moves the ports #{range.first} to #{range.last} " \
            "to #{low} to #{high}, out of 10000 to 65535")
end

root = File.join(dest, 'test')
FileUtils.rm_rf(root)
files = 0
moved = 0
SOURCES.each do |source|
  paths = File.directory?(source) ? Dir.glob(File.join(source, '**', '*'), File::FNM_DOTMATCH) : [source]
  paths.sort.each do |path|
    next if %w[. ..].include?(File.basename(path))

    target = File.join(dest, path)
    if File.directory?(path)
      FileUtils.mkdir_p(target)
      next
    end
    FileUtils.mkdir_p(File.dirname(target))
    content = File.binread(path)
    unless content.include?("\0")
      content.each_line.with_index(1) do |line, number|
        line.scan(UNDERSCORED) do |high, low|
          next unless port?(Integer(high + low, 10))

          finish(1, "#{path}:#{number}: write the port #{high}_#{low} as #{high}#{low}, " \
                    'so that the port offset reaches it')
        end
      end
      content = content.gsub(NUMBER) do
        value = Integer(Regexp.last_match(1), 10)
        next Regexp.last_match(0) unless port?(value)

        moved += 1
        (value + offset).to_s
      end
    end
    File.binwrite(target, content)
    File.chmod(File.stat(path).mode & 0o7777, target)
    files += 1
  end
end
finish(0, "copied #{files} files to #{root}; #{moved} port numbers moved by #{offset}")
