#!/usr/bin/env ruby
# HEAD (or a control GET), then GET /backend on the same connection.
# Uses the existing filter_connection server on port 18112. The first
# response ends at its headers for HEAD, regardless of Content-Length.
# Print STATUS1:HEX1:STATUS2:HEX2, like the other raw socket helpers.
require 'socket'

LIMIT = 60

def read_response(sock)
  raw = ''.b
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + LIMIT
  loop do
    return ['COMPLETE', raw] if yield(raw)

    remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
    return ['TIMEOUT', raw] if remaining <= 0 || !IO.select([sock], nil, nil, remaining)

    chunk = sock.read_nonblock(4096, exception: false)
    return ['EOF', raw] if chunk.nil?
    next if chunk == :wait_readable

    raw << chunk
  end
rescue Errno::ECONNRESET
  ['RESET', raw]
end

method, path = ARGV
abort 'expected HEAD or GET' unless %w[HEAD GET].include?(method)
first_status, first = 'SKIPPED', ''.b
second_status, second = 'SKIPPED', ''.b
begin
  Socket.tcp('127.0.0.1', 18112, connect_timeout: LIMIT) do |sock|
    sock.write "#{method} #{path} HTTP/1.1\r\nHost: localhost\r\n\r\n"
    first_status, first = read_response(sock) do |raw|
      header_end = raw.index("\r\n\r\n")
      if header_end
        length = raw[0, header_end][/^content-length: *(\d+)/i, 1]
        method == 'HEAD' || (length && raw.bytesize >= header_end + 4 + length.to_i)
      end
    end
    if first_status == 'COMPLETE'
      sock.write "GET /backend HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
      second_status, second = read_response(sock) { false }
    end
  end
rescue Errno::ECONNRESET, Errno::EPIPE
  second_status = 'RESET'
rescue Errno::ECONNREFUSED
  first_status = 'REFUSED'
end
puts "#{first_status}:#{first.unpack1('H*')}:#{second_status}:#{second.unpack1('H*')}"
