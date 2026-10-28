#!/usr/bin/env ruby
# Waits for the TCP ports of the test nginx. test.sh runs this file with
# CRuby, like the other helpers in this directory, once before it starts
# nginx and once after, instead of sleeping for a fixed time.
#
# Usage:
#   ruby test/t/cases/_wait_for_listen.rb free LIMIT CONF...
#   ruby test/t/cases/_wait_for_listen.rb listen LIMIT PID CONF...
#
# The ports are those of the "listen" directives in the CONF files, which
# test.sh gives as test/conf/nginx.conf and test/conf/conf.d/*.conf: every
# listen of the http {} block. The stream servers are left out, because a
# connection to a stream server runs that server's session code
# (mruby_stream_code and the like), and the cases observe what that code
# does. nginx opens the listening sockets of http {} and stream {} in one
# loop (ngx_open_listening_sockets), after it has read the whole
# configuration.
#
# free:   waits until no process accepts a connection on the ports, so that
#         the check after the start cannot take another process listening
#         on them for nginx. It fails when one still accepts after LIMIT
#         seconds.
# listen: waits until nginx, started as process PID, accepts a connection on
#         every port. It prints the elapsed time when it does, and fails when
#         LIMIT seconds pass or when the process ends first.
#
# The elapsed time is counted from the start of this script, which test.sh
# runs right after it has started nginx in the background. The script exits
# 0 on success and 1 on a failure, with one line on stdout either way.

require 'socket'

PROBE_TIMEOUT = 1 # seconds for one connection attempt
INTERVAL = 0.1    # seconds between two rounds of attempts

def now
  Process.clock_gettime(Process::CLOCK_MONOTONIC)
end

def finish(status, message)
  puts "wait_for_listen: #{message}"
  exit status
end

# The port of each "listen" directive, as in "listen 18080;",
# "listen 127.0.0.1:12358;" or "listen 18082 ssl;". A listen that this
# script cannot read fails the run instead of being skipped.
def ports_of(files)
  ports = []
  files.each do |file|
    File.foreach(file).with_index(1) do |line, number|
      next unless line =~ /\A\s*listen\s+([^\s;]+)/

      address = Regexp.last_match(1)
      port = address.split(':').last
      finish(1, "cannot read the port of \"listen #{address}\" in #{file}:#{number}") unless port =~ /\A\d+\z/
      ports << Integer(port, 10)
    end
  end
  finish(1, "no listen directive in #{files.join(' ')}") if ports.empty?
  ports.uniq.sort
end

def accepts?(port)
  Socket.tcp('127.0.0.1', port, connect_timeout: PROBE_TIMEOUT).close
  true
rescue Errno::ECONNREFUSED, Errno::ECONNRESET, Errno::ETIMEDOUT
  false
end

# The process is gone, or it has ended and waits for test.sh to collect it
# (a zombie). This script is not its parent, so it cannot wait for it.
def ended?(pid)
  stat = `ps -o stat= -p #{pid} 2>/dev/null`.strip
  stat.empty? || stat.start_with?('Z')
end

def seconds(value)
  format('%.2f', value)
end

mode = ARGV.shift
finish(1, "unknown mode #{mode.inspect}; use free or listen") unless %w[free listen].include?(mode)
limit = Float(ARGV.shift || '')
pid = Integer(ARGV.shift || '', 10) if mode == 'listen'
ports = ports_of(ARGV)
start = now
deadline = start + limit

if mode == 'free'
  loop do
    busy = ports.select { |port| accepts?(port) }
    exit 0 if busy.empty?

    if now > deadline
      finish(1, "before nginx starts, #{busy.size} of #{ports.size} ports still accept connections " \
                "after #{seconds(now - start)} seconds (limit #{seconds(limit)}): #{busy.join(', ')}; " \
                'another process listens on them')
    end
    sleep INTERVAL
  end
end

waiting = ports.dup
loop do
  waiting.reject! { |port| accepts?(port) }
  if waiting.empty?
    finish(0, "nginx (pid #{pid}) accepted connections on all #{ports.size} ports " \
              "after #{seconds(now - start)} seconds (limit #{seconds(limit)})")
  end
  if ended?(pid)
    finish(1, "nginx (pid #{pid}) ended after #{seconds(now - start)} seconds, before it accepted " \
              "connections on #{waiting.size} of #{ports.size} ports: #{waiting.join(', ')}; " \
              'see its output above and logs/error.log')
  end
  if now > deadline
    finish(1, "nginx (pid #{pid}) did not accept connections within #{seconds(limit)} seconds " \
              "(NGINX_HEATTIME) on #{waiting.size} of #{ports.size} ports: #{waiting.join(', ')}")
  end
  sleep INTERVAL
end
