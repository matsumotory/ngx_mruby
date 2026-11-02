# frozen_string_literal: true

# Checks the TCP response/EOF contract and counter validation without nginx.
require_relative 'tcp_client'

class StreamClientTest
  def assert(value)
    raise 'assertion failed' unless value
  end

  def refute(value)
    assert(!value)
  end

  def assert_equal(expected, actual)
    raise "got #{actual.inspect}, expected #{expected.inspect}" unless actual == expected
  end

  def assert_match(pattern, text)
    assert(pattern.match?(text))
  end

  def assert_raises(*classes)
    begin
      yield
    rescue *classes => e
      return e
    end
    raise "expected #{classes.join(' or ')}"
  end

  def with_peer
    server = TCPServer.new('127.0.0.1', 0)
    peer = Thread.new do
      socket = server.accept
      yield socket, nil
    ensure
      socket&.close
    end
    yield nil, server.addr[1]
  ensure
    peer&.kill
    peer&.join
    server&.close
  end

  def test_fragmented_response_and_eof
    with_peer do |socket, port|
      if socket
        socket.write('str')
        socket.write('eam')
      else
        assert_equal 'stream', StreamClient.check(port, 'stream', io_timeout: 1)
      end
    end
  end

  def test_wrong_short_and_extra_responses
    ['strea', 'streaX', 'streamX'].each do |response|
      with_peer do |socket, port|
        if socket
          socket.write(response)
        else
          assert_raises(StreamClient::Error) { StreamClient.check(port, 'stream', io_timeout: 1) }
        end
      end
    end
  end

  def test_exact_bytes_without_eof_time_out
    with_peer do |socket, port|
      if socket
        socket.write('stream')
        socket.read # the client must close even when its EOF wait times out
      else
        error = assert_raises(StreamClient::Error) { StreamClient.check(port, 'stream', io_timeout: 0.05) }
        assert_match(/no complete response/, error.message)
      end
    end
  end

  def test_connection_reset_is_not_eof
    with_peer do |socket, port|
      if socket
        socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack('ii'))
      else
        assert_raises(Errno::ECONNRESET, StreamClient::Error) { StreamClient.check(port, 'stream', io_timeout: 1) }
      end
    end
  end

  def test_counter_values_are_required_and_nonnegative_integers
    assert StreamCounters.zero?(stream_timers: 0, stream_fibers: 0)
    refute StreamCounters.zero?(stream_timers: 1, stream_fibers: 1)
    [nil, -1, '0', 0.0].each do |bad|
      StreamCounters::KEYS.each do |key|
        stats = { stream_timers: 0, stream_fibers: 0 }.merge(key => bad)
        assert_raises(StreamClient::Error) { StreamCounters.zero?(stats) }
      end
    end
    assert_raises(StreamClient::Error) { StreamCounters.zero?({}) }
  end
end

failures = []
checks = StreamClientTest.new
cases = checks.methods.grep(/^test_/).sort
cases.each do |name|
  checks.public_send(name)
rescue StandardError => e
  failures << "#{name}: #{e.class}: #{e.message}"
end
failures.each { |failure| warn "tcp_client_test: #{failure}" }
puts "tcp_client_test: #{cases.size} cases, #{failures.size} failures"
exit(failures.empty? ? 0 : 1)
