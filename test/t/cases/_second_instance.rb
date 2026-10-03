#!/usr/bin/env ruby
# Starts a second nginx with a generated configuration, observes it, and stops
# it. test/t/cases/directives.rb and test/t/cases/stream.rb run this file with
# CRuby, because the test build of mruby has no Process module, so it cannot
# send a signal to nginx or wait for nginx to end. The nginx that test.sh
# starts already has inline init hooks, and a second hook of the same kind
# would replace them or be rejected. The second nginx therefore shows what the
# first one cannot: the file versions of the init, init_worker and exit_worker
# hooks, and the order in which the hooks run.
#
# Usage: ruby test/t/cases/_second_instance.rb http|stream
#
# NGINX_INSTALL_DIR names the nginx that test.sh installed. The second nginx
# runs in the foreground as a single process, uses the prefix
# NGINX_INSTALL_DIR/second_instance/MODE/ and listens on 127.0.0.1:58116 for
# http or on 127.0.0.1:12357 for stream. The hook files are the copies of
# test/html in NGINX_INSTALL_DIR/html. A dynamic module build loads the
# module with an absolute path.
#
# The script prints one "key=value" line for each observation:
#   reply   what the second nginx answered: the HTTP body for http, the bytes
#           of the stream session for stream
#   trace   stream only: the trace that the session code wrote to error.log
#   stdout  the lines that the hooks printed with p, joined with "|"
#   exit    "exited N" or "ended by signal N" after SIGQUIT, or why the
#           process did not end
#   error   only when a step failed; the other keys may then be missing

require 'socket'
require 'fileutils'

LIMIT = 30 # seconds for the start, for each exchange and for the stop
PORTS = { 'http' => 58116, 'stream' => 12357 }.freeze

HTTP_CONF = <<'CONF'
http {
    access_log off;

    mruby_init __HTML__/directives_init.rb;
    mruby_init_worker __HTML__/directives_init_worker.rb;
    mruby_exit_worker __HTML__/directives_exit_worker.rb;

    server {
        listen 127.0.0.1:__PORT__;

        # The hook files append to $init_order in the order they run.
        location /init_order {
            mruby_content_handler_code 'Nginx.rputs $init_order.join(",")';
        }
    }
}
CONF

# Each inline *_code directive comes before the file version of the same
# hook. nginx accepts both in a stream block, and the later one replaces the
# earlier one, so only the file versions run. The empty http block is there
# because the nginx built with this module does not start without one.
STREAM_CONF = <<'CONF'
http {
}

stream {
    mruby_stream_init_code '
        p "mruby_stream_init_code"
        Userdata.new.init_trace = "#{Userdata.new.init_trace},init_code"
    ';
    mruby_stream_init __HTML__/stream_init.rb;

    mruby_stream_init_worker_code '
        p "mruby_stream_init_worker_code"
        Userdata.new.init_trace = "#{Userdata.new.init_trace},init_worker_code"
    ';
    mruby_stream_init_worker __HTML__/stream_init_worker.rb;

    mruby_stream_exit_worker_code 'p "mruby_stream_exit_worker_code"';
    mruby_stream_exit_worker __HTML__/stream_exit_worker.rb;

    server {
        listen 127.0.0.1:__PORT__;

        # This code runs while nginx reads the configuration, before every
        # init hook, and starts the trace that the hook files extend.
        mruby_stream_server_context_code 'Userdata.new.init_trace = "server_context_code"';

        mruby_stream_code 'Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "init trace=[#{Userdata.new.init_trace}]"';
        return "stream session ok";
    }
}
CONF

def now
  Process.clock_gettime(Process::CLOCK_MONOTONIC)
end

def configuration(mode, install, prefix)
  html = File.join(install, 'html')
  port = PORTS.fetch(mode).to_s
  so = File.join(install, 'modules', 'ngx_http_mruby_module.so')
  body = mode == 'http' ? HTTP_CONF : STREAM_CONF
  [
    File.exist?(so) ? "load_module #{so};" : '',
    'daemon off;',
    'master_process off;',
    'worker_processes 1;',
    "pid #{prefix}nginx.pid;",
    "error_log #{prefix}error.log notice;",
    'events { worker_connections 64; }',
    body.gsub('__HTML__', html).gsub('__PORT__', port),
  ].join("\n")
end

def describe(status)
  status.signaled? ? "ended by signal #{status.termsig}" : "exited #{status.exitstatus}"
end

def port_open?(port)
  TCPSocket.new('127.0.0.1', port).close
  true
rescue Errno::ECONNREFUSED
  false
end

def read_until_close(sock)
  deadline = now + LIMIT
  data = ''.b
  loop do
    remaining = deadline - now
    raise "no close from nginx within #{LIMIT} seconds" if remaining <= 0
    next unless IO.select([sock], nil, nil, remaining)

    chunk = sock.read_nonblock(4096, exception: false)
    return data if chunk.nil?
    next if chunk == :wait_readable

    data << chunk
  end
end

def exchange(port, payload)
  Socket.tcp('127.0.0.1', port, connect_timeout: LIMIT) do |sock|
    sock.write(payload) unless payload.empty?
    read_until_close(sock)
  end
end

class SecondInstance
  attr_reader :result

  def initialize(mode)
    @mode = mode
    @port = PORTS.fetch(mode)
    @install = ENV.fetch('NGINX_INSTALL_DIR')
    @prefix = File.join(@install, 'second_instance', mode) + '/'
    @pid = nil
    @status = nil
    @result = {}
  end

  def run
    start
    observe
  rescue StandardError => e
    @result['error'] = e.message.gsub("\n", ' ')
  ensure
    @result['exit'] = stop if @pid
    collect
  end

  private

  def start
    raise "port #{@port} is already in use" if port_open?(@port)

    FileUtils.rm_rf(@prefix)
    FileUtils.mkdir_p(@prefix)
    conf = File.join(@prefix, 'nginx.conf')
    File.write(conf, configuration(@mode, @install, @prefix))
    @pid = Process.spawn(File.join(@install, 'sbin', 'nginx'),
                         '-p', @prefix, '-c', conf, '-e', File.join(@prefix, 'error.log'),
                         out: File.join(@prefix, 'stdout.log'),
                         err: File.join(@prefix, 'stderr.log'))
    wait_for_listen
  end

  def wait_for_listen
    deadline = now + LIMIT
    loop do
      if Process.waitpid(@pid, Process::WNOHANG)
        @status = $?
        raise "nginx ended during the start: #{describe(@status)}"
      end
      return if port_open?(@port)
      raise "nginx did not listen on #{@port} within #{LIMIT} seconds" if now > deadline

      sleep 0.1
    end
  end

  def observe
    if @mode == 'http'
      raw = exchange(@port, "GET /init_order HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
      @result['reply'] = raw.split("\r\n\r\n", 2)[1].to_s
    else
      @result['reply'] = exchange(@port, '')
    end
  end

  # Sends SIGQUIT, which makes the single nginx process run the exit_worker
  # hooks and exit, and waits for it. A process that does not exit in time
  # gets SIGKILL, so no nginx stays behind.
  def stop
    return describe(@status) if @status

    Process.kill(:QUIT, @pid)
    deadline = now + LIMIT
    loop do
      return describe($?) if Process.waitpid(@pid, Process::WNOHANG)

      if now > deadline
        Process.kill(:KILL, @pid)
        Process.waitpid(@pid)
        return "killed after #{LIMIT} seconds"
      end
      sleep 0.1
    end
  rescue Errno::ESRCH, Errno::ECHILD
    'gone before SIGQUIT'
  end

  # The hooks print with p, and nginx flushes stdout when it exits, so the
  # file is complete only after stop.
  def collect
    stdout = File.join(@prefix, 'stdout.log')
    if File.exist?(stdout)
      @result['stdout'] = File.read(stdout).split("\n").reject(&:empty?).join('|')
    end
    log = File.join(@prefix, 'error.log')
    return unless @mode == 'stream' && File.exist?(log)

    # error.log also holds the source of the session code, so the pattern
    # accepts only the characters of a trace.
    m = File.read(log).match(/init trace=\[([a-z_,]*)\]/)
    @result['trace'] = m[1] if m
  end
end

mode = ARGV[0]
unless PORTS.key?(mode)
  puts "error=unknown mode #{mode.inspect}"
  exit 1
end

instance = SecondInstance.new(mode)
instance.run
%w[error reply trace stdout exit].each do |key|
  puts "#{key}=#{instance.result[key]}" if instance.result.key?(key)
end
