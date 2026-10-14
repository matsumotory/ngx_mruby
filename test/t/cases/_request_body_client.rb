#!/usr/bin/env ruby
# Raw TCP client for test/t/cases/request_body_later.rb. It runs with CRuby,
# like test/t/cases/_tcp_client.rb.
#
# Usage: ruby test/t/cases/_request_body_client.rb MODE PORT HOST PATH [COUNT]
#        ruby test/t/cases/_request_body_client.rb close_wait PORT
#
# parts: sends a POST to 127.0.0.1:PORT whose 20-byte body is written in two
#   halves, WAIT seconds apart, so that the handler starts before the body is
#   complete. It reads until the server closes the connection or LIMIT
#   seconds pass, and prints "STATUS:HEX" as _tcp_client.rb does.
# whole: the same request, with the headers and the whole body written at
#   once, so that nginx reads the body together with the headers.
# bad_chunk: a POST with HTTP/1.1 and a chunked body: the headers and a
#   valid first chunk, then, WAIT seconds later, a line that is not a chunk
#   size, so that nginx rejects the body with 400 after the handler started.
#   It reads and prints as "parts" does.
# keepalive: the request of "parts" with HTTP/1.1 and a kept connection. It
#   reads the response up to the end of its Content-Length, then sends
#   "GET /plain" with "Connection: close" on the same connection and reads
#   until the server closes it. It prints "STATUS1:HEX1:STATUS2:HEX2": the
#   first STATUS is COMPLETE when the first response arrived whole, the
#   second one is that of the connection after the second request.
# timeout: sends the headers of a POST with a 100-byte body and the first 10
#   bytes of it, then reads until the server closes the connection or LIMIT
#   seconds pass. It prints "STATUS:SECONDS:HEX", SECONDS being the time
#   from the last write to the end of the read.
# close: opens COUNT connections that each send the headers of a POST with a
#   100-byte body and the first 10 bytes of that body, waits WAIT seconds so
#   that the handler starts, and closes them. It then reads /proc/net/tcp
#   until no more sockets with the local port PORT are in CLOSE_WAIT than
#   before the connections were opened, or LIMIT seconds pass, and prints
#   "before=N after=M". A socket in CLOSE_WAIT is the server side of a
#   connection whose client has closed it while nginx still keeps it open.
#   Without /proc/net/tcp (not Linux) it prints "unsupported".
# close_wait: reads /proc/net/tcp until no socket with the local port PORT is
#   in CLOSE_WAIT, or LIMIT seconds pass, and prints "close_wait=N" with the
#   last count. Without /proc/net/tcp it prints "unsupported".
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
when 'close_wait'
  unless File.readable?('/proc/net/tcp')
    print 'unsupported'
    exit
  end
  deadline = now + LIMIT
  count = close_wait_count(port)
  while count > 0 && now < deadline
    sleep 0.1
    count = close_wait_count(port)
  end
  print "close_wait=#{count}"
when 'parts', 'whole', 'bad_chunk'
  body = '0123456789abcdefghij'
  head = "POST #{path} HTTP/1.0\r\nHost: #{host}\r\nContent-Length: #{body.bytesize}\r\n\r\n"
  received = ''.b
  status =
    begin
      Socket.tcp('127.0.0.1', port, connect_timeout: LIMIT) do |sock|
        case mode
        when 'whole'
          sock.write(head + body)
        when 'parts'
          sock.write(head + body[0, 10])
          sleep WAIT
          sock.write(body[10..])
        else
          sock.write("POST #{path} HTTP/1.1\r\nHost: #{host}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabcde\r\n")
          sleep WAIT
          sock.write("zz\r\n")
        end
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
when 'keepalive'
  body = '0123456789abcdefghij'
  head = "POST #{path} HTTP/1.1\r\nHost: #{host}\r\nContent-Length: #{body.bytesize}\r\n\r\n"
  first = ''.b
  second = ''.b
  status1 = 'TIMEOUT'
  status2 = 'SKIPPED'
  begin
    Socket.tcp('127.0.0.1', port, connect_timeout: LIMIT) do |sock|
      sock.write(head + body[0, 10])
      sleep WAIT
      sock.write(body[10..])
      deadline = now + LIMIT
      loop do
        if (header_end = first.index("\r\n\r\n"))
          length = first[0, header_end][/^content-length: *(\d+)/i, 1]
          if length && first.bytesize >= header_end + 4 + length.to_i
            status1 = 'COMPLETE'
            break
          end
        end
        remaining = deadline - now
        break if remaining <= 0
        break unless IO.select([sock], nil, nil, remaining)

        chunk = sock.read_nonblock(4096, exception: false)
        if chunk.nil?
          status1 = 'EOF'
          break
        end
        next if chunk == :wait_readable

        first << chunk
      end
      if status1 == 'COMPLETE'
        sock.write("GET /plain HTTP/1.1\r\nHost: #{host}\r\nConnection: close\r\n\r\n")
        deadline = now + LIMIT
        status2 = loop do
          remaining = deadline - now
          break 'TIMEOUT' if remaining <= 0
          break 'TIMEOUT' unless IO.select([sock], nil, nil, remaining)

          chunk = sock.read_nonblock(4096, exception: false)
          break 'EOF' if chunk.nil?
          next if chunk == :wait_readable

          second << chunk
        end
      end
    end
  rescue Errno::ECONNRESET, Errno::EPIPE
    status2 = 'RESET'
  rescue Errno::ECONNREFUSED
    status1 = 'REFUSED'
  end
  print "#{status1}:#{first.unpack1('H*')}:#{status2}:#{second.unpack1('H*')}"
when 'timeout'
  received = ''.b
  started = nil
  status =
    begin
      Socket.tcp('127.0.0.1', port, connect_timeout: LIMIT) do |sock|
        sock.write("POST #{path} HTTP/1.0\r\nHost: #{host}\r\nContent-Length: 100\r\n\r\n0123456789")
        started = now
        deadline = started + LIMIT
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
  seconds = started ? now - started : 0
  print "#{status}:#{format('%.1f', seconds)}:#{received.unpack1('H*')}"
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
