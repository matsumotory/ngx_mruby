#!/usr/bin/env ruby
# Raw TCP client for test/t/cases/request_body_later.rb. It runs with CRuby,
# like test/t/cases/_tcp_client.rb.
#
# Usage: ruby test/t/cases/_request_body_client.rb MODE PORT HOST PATH [COUNT]
#
# parts: sends a POST to 127.0.0.1:PORT whose 20-byte body is written in two
#   halves, WAIT seconds apart, so that the handler starts before the body is
#   complete. It reads until the server closes the connection or LIMIT
#   seconds pass, and prints "STATUS:HEX" as _tcp_client.rb does.
# close: opens COUNT connections that each send the headers of a POST with a
#   100-byte body and the first 10 bytes of that body, waits WAIT seconds so
#   that the handler starts, and closes them. It then reads /proc/net/tcp
#   until no more sockets with the local port PORT are in CLOSE_WAIT than
#   before the connections were opened, or LIMIT seconds pass, and prints
#   "before=N after=M". A socket in CLOSE_WAIT is the server side of a
#   connection whose client has closed it while nginx still keeps it open.
#   Without /proc/net/tcp (not Linux) it prints "unsupported".
#
# LIMIT only bounds a run that already fails. It is long enough for nginx
# under valgrind.

require 'socket'

LIMIT = 15
WAIT = 1.0
TCP_CLOSE_WAIT = '08'

def now
  Process.clock_gettime(Process::CLOCK_MONOTONIC)
end

def close_wait_count(port)
  File.readlines('/proc/net/tcp').drop(1).count do |line|
    fields = line.split
    fields[1].split(':')[1].to_i(16) == port && fields[3] == TCP_CLOSE_WAIT
  end
end

mode = ARGV[0]
port = Integer(ARGV[1])
host = ARGV[2]
path = ARGV[3]

case mode
when 'parts'
  body = '0123456789abcdefghij'
  head = "POST #{path} HTTP/1.0\r\nHost: #{host}\r\nContent-Length: #{body.bytesize}\r\n\r\n"
  received = ''.b
  status =
    begin
      Socket.tcp('127.0.0.1', port, connect_timeout: LIMIT) do |sock|
        sock.write(head + body[0, 10])
        sleep WAIT
        sock.write(body[10..])
        deadline = now + LIMIT
        loop do
          remaining = deadline - now
          break 'TIMEOUT' if remaining <= 0
          break 'TIMEOUT' unless IO.select([sock], nil, nil, remaining)

          chunk = sock.read_nonblock(4096, exception: false)
          break 'EOF' if chunk.nil?
          next if chunk == :wait_readable

          received << chunk
        end
      end
    rescue Errno::ECONNRESET, Errno::EPIPE
      'RESET'
    rescue Errno::ECONNREFUSED
      'REFUSED'
    end
  print "#{status}:#{received.unpack1('H*')}"
when 'close'
  unless File.readable?('/proc/net/tcp')
    print 'unsupported'
    exit
  end
  count = Integer(ARGV[4])
  before = close_wait_count(port)
  socks = Array.new(count) do
    sock = Socket.tcp('127.0.0.1', port, connect_timeout: LIMIT)
    sock.write("POST #{path} HTTP/1.0\r\nHost: #{host}\r\nContent-Length: 100\r\n\r\n0123456789")
    sock
  end
  sleep WAIT
  socks.each(&:close)
  deadline = now + LIMIT
  after = close_wait_count(port)
  while after > before && now < deadline
    sleep 0.1
    after = close_wait_count(port)
  end
  print "before=#{before} after=#{after}"
else
  abort "unknown mode #{mode}"
end
