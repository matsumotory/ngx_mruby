# frozen_string_literal: true

# One completed TCP session for the stream soak/performance scenarios. Each
# response must match byte for byte and end in EOF, within one total deadline.
require 'socket'
require 'io/wait'

class StreamClient
  class Error < StandardError; end

  def self.check(port, expected, io_timeout: 30)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + io_timeout
    socket = Socket.tcp('127.0.0.1', port, connect_timeout: io_timeout)
    received = +''.b
    loop do
      remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      raise Error, "TCP #{port}: no complete response within #{io_timeout} s" unless remaining.positive?

      chunk = socket.read_nonblock([expected.bytesize + 1 - received.bytesize, 1].max, exception: false)
      case chunk
      when :wait_readable
        raise Error, "TCP #{port}: no complete response within #{io_timeout} s" unless socket.wait_readable(remaining)
      when nil
        raise Error, "TCP #{port}: unexpected response #{received.inspect}, expected #{expected.inspect}" unless received == expected.b

        return received
      else
        received << chunk
        raise Error, "TCP #{port}: response exceeds #{expected.bytesize} bytes" if received.bytesize > expected.bytesize
      end
    end
  ensure
    socket&.close
  end
end

module StreamCounters
  KEYS = %i[stream_timers stream_fibers].freeze

  def self.read(stats)
    KEYS.map do |key|
      value = stats[key]
      unless value.is_a?(Integer) && value >= 0
        raise StreamClient::Error, "Nginx::Debug.stats #{key}: expected a nonnegative Integer, got #{value.inspect}"
      end
      value
    end
  end

  def self.zero?(stats)
    read(stats).all?(&:zero?)
  end
end
