# frozen_string_literal: true

# A minimal HTTP/1.1 client (CRuby) for the memory soak test
# (test/soak/soak.rb) and the performance comparison (test/perf/perf.rb):
# one connection, one request at a time.

require 'io/wait'
require 'socket'

class Client
  # Raised when no response arrives within io_timeout seconds.
  class Timeout < StandardError; end

  def initialize(port, io_timeout: 30)
    @io_timeout = io_timeout
    @sock = Socket.tcp('127.0.0.1', port, connect_timeout: 5)
    @sock.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
    @buf = String.new(encoding: Encoding::BINARY)
  end

  def close
    @sock.close unless @sock.closed?
  end

  # Returns [status, headers, body, keep_alive]. With close: true the request
  # asks the server to close, and the response is read to EOF, so the server
  # has closed its socket when this returns.
  def get(path, headers = {}, close: false)
    request('GET', path, headers, nil, close: close)
  end

  # The same as get for any method; body (a String or nil) is sent with a
  # Content-Length, in the same write as the request head.
  def request(method, path, headers = {}, body = nil, close: false)
    @sock.write(build_request(method, path, headers, body, close))
    status, response_headers, response_body = read_response
    keep_alive = response_headers['connection'].to_s.downcase != 'close'
    read_to_eof if close || !keep_alive
    [status, response_headers, response_body, keep_alive && !close]
  end

  # Sends a request, reads the response head and then the body until the
  # block returns true for the body read so far (decoded, when chunked) or
  # the body ends. Returns [status, headers, body, ending], where ending is
  # :complete (the whole body arrived), :stopped (the block returned true
  # first), :cut (the server closed the connection before the end of the
  # body) or :reset (the server reset the connection before the end of the
  # body). The caller closes the client afterwards: the connection is not in
  # a state for another request.
  def stream(method, path, headers = {}, body = nil, &stop)
    @sock.write(build_request(method, path, headers, body, true))
    status, response_headers = read_head
    received = String.new(encoding: Encoding::BINARY)
    ending = begin
      if response_headers['transfer-encoding'].to_s.downcase.include?('chunked')
        read_chunked(received, stop)
      else
        read_until_close(received, stop)
      end
    rescue EOFError
      :cut
    rescue Errno::ECONNRESET
      :reset
    end
    [status, response_headers, received, ending]
  end

  # Sends a request and closes the connection without reading the response.
  def send_and_close(path, headers = {})
    @sock.write(build_request('GET', path, headers, nil, true))
    close
  end

  private

  # A Host in headers (any case) replaces the default "Host: localhost".
  def build_request(method, path, headers, body, close)
    req = +"#{method} #{path} HTTP/1.1\r\n"
    req << "Host: localhost\r\n" unless headers.keys.any? { |k| k.casecmp?('host') }
    headers.each { |k, v| req << "#{k}: #{v}\r\n" }
    req << "Content-Length: #{body.bytesize}\r\n" if body
    req << "Connection: close\r\n" if close
    req << "\r\n"
    req << body if body
    req
  end

  def fill
    loop do
      chunk = @sock.read_nonblock(65_536, exception: false)
      case chunk
      when :wait_readable
        raise Timeout, "no response within #{@io_timeout} s" unless @sock.wait_readable(@io_timeout)
      when nil
        raise EOFError, 'connection closed by the server'
      else
        @buf << chunk
        return
      end
    end
  end

  def take(size)
    fill while @buf.bytesize < size
    @buf.slice!(0, size)
  end

  def take_line
    fill until (idx = @buf.index("\r\n"))
    @buf.slice!(0, idx + 2).chomp("\r\n")
  end

  def read_head
    fill until (idx = @buf.index("\r\n\r\n"))
    lines = @buf.slice!(0, idx + 4).split("\r\n")
    status = lines.shift.to_s[%r{\AHTTP/1\.[01] (\d{3})}, 1].to_i
    headers = {}
    lines.each do |line|
      key, value = line.split(':', 2)
      headers[key.strip.downcase] = value.to_s.strip
    end
    [status, headers]
  end

  def read_response
    status, headers = read_head
    body = if headers['transfer-encoding'].to_s.downcase.include?('chunked')
             read_chunked(String.new(encoding: Encoding::BINARY))
           elsif headers.key?('content-length')
             take(Integer(headers['content-length'], 10))
           else
             read_to_eof
           end
    [status, headers, body]
  end

  # Appends the decoded chunks to body. Without stop, returns body at the
  # last chunk. With stop, asks stop after each chunk and returns :stopped
  # when it returns true, or :complete at the last chunk.
  def read_chunked(body, stop = nil)
    loop do
      size = take_line.split(';', 2).first.to_i(16)
      if size.zero?
        nil until take_line.empty? # trailer section
        return stop ? :complete : body
      end
      body << take(size)
      take_line
      return :stopped if stop&.call(body)
    end
  end

  def read_until_close(body, stop)
    loop do
      body << @buf.slice!(0, @buf.bytesize)
      return :stopped if stop.call(body)

      fill
    end
  rescue EOFError
    body << @buf.slice!(0, @buf.bytesize)
    :complete
  end

  def read_to_eof
    loop { fill }
  rescue EOFError
    @buf.slice!(0, @buf.bytesize)
  end
end
