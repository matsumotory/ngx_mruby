#!/usr/bin/env ruby
# Raw TCP client for test/t/cases/stream.rb. It runs with CRuby, because the
# test build of mruby has no socket read with a deadline.
#
# Usage: ruby test/t/cases/_stream_client.rb PORT [HEX_PAYLOAD]
#
# The client connects to 127.0.0.1:PORT, writes the payload decoded from hex,
# and reads until the server closes the connection or five seconds pass. It
# prints "STATUS:HEX". STATUS is EOF, RESET, REFUSED or TIMEOUT, and HEX is
# everything the client received, encoded as hex so that the caller can
# compare the exact bytes.

require 'socket'

port = Integer(ARGV[0])
payload = [ARGV[1] || ''].pack('H*')
received = ''.b
deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5

status =
  begin
    Socket.tcp('127.0.0.1', port, connect_timeout: 5) do |sock|
      sock.write(payload) unless payload.empty?
      loop do
        remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
        break 'TIMEOUT' if remaining <= 0
        break 'TIMEOUT' unless IO.select([sock], nil, nil, remaining)

        chunk = sock.read_nonblock(4096, exception: false)
        break 'EOF' if chunk.nil?
        next if chunk == :wait_readable

        received << chunk
      end
    end
  rescue Errno::ECONNRESET
    'RESET'
  rescue Errno::ECONNREFUSED
    'REFUSED'
  end

print "#{status}:#{received.unpack1('H*')}"
