#!/usr/bin/env ruby
# Starts a second nginx with a generated configuration, observes it, and stops
# it. test/t/cases/directives.rb and test/t/cases/stream.rb run this file with
# CRuby, because the test build of mruby has no Process module, so it cannot
# send a signal to nginx or wait for nginx to end. The nginx that test.sh
# starts already has inline init hooks, and a second hook of the same kind
# would replace them or be rejected. The second nginx therefore shows what the
# first one cannot: the file versions of the init, init_worker and exit_worker
# hooks, and the order in which the hooks run. The mode stream_master runs a
# master process and a worker process, for stream cases that need the worker
# to shut down (worker_shutdown_timeout) or a worker process of its own.
#
# Usage: ruby test/t/cases/_second_instance.rb http|stream|stream_add_listener|stream_master
#
# NGINX_INSTALL_DIR names the nginx that test.sh installed. The second nginx
# runs in the foreground, uses the prefix
# NGINX_INSTALL_DIR/second_instance/MODE/ and listens on 127.0.0.1:18116 for
# http, on 127.0.0.1:12357 for the modes stream and stream_add_listener, and on
# 127.0.0.1:12385 to 12388 for stream_master. It runs as a single process,
# except in stream_master, where it has a master process and one worker
# process. The hook files are the copies of test/html in
# NGINX_INSTALL_DIR/html. A dynamic module build loads the module with an
# absolute path.
#
# The script prints one "key=value" line for each observation:
#   reply   what the second nginx answered: the HTTP body for http, the bytes
#           of the stream session for stream
#   trace   stream only: the trace that the session code wrote to error.log
#   add_listener  stream_add_listener only: what Nginx::Stream.add_listener
#           did when the session code called it, as the code wrote it to
#           error.log ("returned" or "CLASS: MESSAGE")
#   stdout  the lines that the hooks printed with p, joined with "|"
#   pp_unknown, pp_local, pp_none, pp_tcp4  stream_master only: the bytes of
#           a session on port 12385 (proxy_protocol) after the header
#           "PROXY UNKNOWN", after a version 2 LOCAL header and after a TCP4
#           header, and of a session on port 12386 (without proxy_protocol)
#   pp_values  stream_master only: what the code of those four sessions
#           logged for proxy_protocol_addr and proxy_protocol_ip, in that
#           order, joined with "|"
#   wait_pp, wait_plain  stream_master only: the bytes of the sessions on
#           port 12387 (proxy_protocol) and 12388 (without it) whose code
#           sleeps when nginx gets SIGQUIT
#   started stream_master only: how many times the code of those sessions
#           logged that it started
#   quit_seconds  stream_master only: the seconds from SIGQUIT until the
#           master process exited
#   worker_signals  stream_master only: how many times error.log says that a
#           worker process exited on a signal
#   exit    "exited N" or "ended by signal N" after SIGQUIT, or why the
#           process did not end
#   error   only when a step failed; the other keys may then be missing

require 'socket'
require 'fileutils'

LIMIT = 30 # seconds for the start, for each exchange and for the stop
PORTS = { 'http' => 18116, 'stream' => 12357, 'stream_add_listener' => 12357, 'stream_master' => 12385 }.freeze

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

# Nginx::Stream.add_listener at run time. The server has no listen
# directive: its mruby_stream_server_context_code adds the listener while
# nginx reads the configuration, the use that the method is for. The session
# code then calls the method again and writes what happened to error.log.
# Running it in the second nginx keeps the nginx of test.sh and the later
# case files out of whatever the call does there.
STREAM_ADD_LISTENER_CONF = <<'CONF'
http {
}

stream {
    server {
        mruby_stream_server_context_code 'Nginx::Stream.add_listener({address: "127.0.0.1:__PORT__"})';

        mruby_stream_code '
            begin
              Nginx::Stream.add_listener({address: "127.0.0.1:__PORT__"})
              result = "returned"
            rescue => e
              result = "#{e.class}: #{e.message}"
            end
            Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "add_listener in a session: [#{result}]"
        ';
        return "stream session ok";
    }
}
CONF

# A master process and one worker, and worker_shutdown_timeout 1s.
# Ports 12385 (proxy_protocol) and 12386 (without it): the code reads
# proxy_protocol_addr and proxy_protocol_ip with the class and the instance
# methods and logs what they gave; the session goes on when the four agree.
# Ports 12387 (proxy_protocol) and 12388 (without it): the code logs a line
# and sleeps 10 seconds, much longer than the timeout. After SIGQUIT, the
# worker shuts down, and when the timeout expires nginx sets c->close on each
# session and calls its read handler: the session ends then, before the
# return directive runs, and the worker exits.
STREAM_MASTER_CONF = <<'CONF'
worker_shutdown_timeout 1s;

http {
}

stream {
    upstream stream_master_backend {
        server 127.0.0.1:12386;
    }

    server {
        listen 127.0.0.1:12385 proxy_protocol;
        listen 127.0.0.1:12386;
        mruby_stream_code '
            k = Nginx::Stream::Connection
            c = k.new "stream_master_backend"
            values = [k.proxy_protocol_addr, k.proxy_protocol_ip, c.proxy_protocol_addr, c.proxy_protocol_ip]
            Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "pp values: #{values.inspect}"
            k.stream_status = Nginx::Stream::ABORT unless values.uniq.size == 1
        ';
        return "pp $proxy_protocol_addr";
    }

    server {
        listen 127.0.0.1:12387 proxy_protocol;
        listen 127.0.0.1:12388;
        mruby_stream_code '
            Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "shutdown case: the code started on #{Nginx::Stream::Connection.local_port}"
            Nginx::Stream::Async.sleep 10000
            Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "shutdown case: the code resumed"
        ';
        return "slept";
    }
}
CONF

PP_V2_LOCAL = "\r\n\r\n\x00\r\nQUIT\n\x20\x00\x00\x00".b

def now
  Process.clock_gettime(Process::CLOCK_MONOTONIC)
end

def configuration(mode, install, prefix)
  html = File.join(install, 'html')
  port = PORTS.fetch(mode).to_s
  so = File.join(install, 'modules', 'ngx_http_mruby_module.so')
  body = { 'http' => HTTP_CONF, 'stream' => STREAM_CONF,
           'stream_master' => STREAM_MASTER_CONF }.fetch(mode, STREAM_ADD_LISTENER_CONF)
  [
    File.exist?(so) ? "load_module #{so};" : '',
    'daemon off;',
    mode == 'stream_master' ? 'master_process on;' : 'master_process off;',
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
    return observe_master if @mode == 'stream_master'

    if @mode == 'http'
      raw = exchange(@port, "GET /init_order HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
      @result['reply'] = raw.split("\r\n\r\n", 2)[1].to_s
    else
      @result['reply'] = exchange(@port, '')
    end
  end

  # stream_master: the sessions without a PROXY source address, one after
  # the other, then the two sessions whose code sleeps; when the code of both
  # has logged that it started, SIGQUIT, and the time until the master
  # process exits.
  def observe_master
    @result['pp_unknown'] = session(12385, "PROXY UNKNOWN\r\n")
    @result['pp_local'] = session(12385, PP_V2_LOCAL)
    @result['pp_none'] = session(12386, '')
    @result['pp_tcp4'] = session(12385, "PROXY TCP4 192.0.2.10 127.0.0.1 40000 12385\r\n")
    # error.log also holds the source of the session code, so the pattern
    # accepts only what an inspect of the four values gives.
    log = File.join(@prefix, 'error.log')
    @result['pp_values'] = File.read(log).scan(/pp values: (\[[a-z0-9 ,."]*\])/).flatten.join('|')

    wait_pp = Thread.new { session(12387, "PROXY TCP4 192.0.2.10 127.0.0.1 40000 12387\r\n") }
    wait_plain = Thread.new { session(12388, '') }
    deadline = now + LIMIT
    until started_lines(log) >= 2
      raise "the code of the sessions did not start within #{LIMIT} seconds" if now > deadline

      sleep 0.05
    end
    quit_at = now
    @result['exit'] = stop
    @result['quit_seconds'] = format('%.2f', now - quit_at)
    @result['wait_pp'] = wait_pp.value
    @result['wait_plain'] = wait_plain.value
    @result['started'] = started_lines(log).to_s
    @result['worker_signals'] = File.read(log).scan(/worker process [0-9]+ exited on signal/).size.to_s
  end

  def session(port, payload)
    exchange(port, payload)
  rescue StandardError => e
    "<#{e.class}: #{e.message}>"
  end

  # error.log also holds the source of the session code, so the pattern
  # accepts only a port number after the text.
  def started_lines(log)
    return 0 unless File.exist?(log)

    File.read(log).scan(/shutdown case: the code started on [0-9]+/).size
  end

  # Sends SIGQUIT and waits for nginx to exit. A single nginx process runs the
  # exit_worker hooks and exits; a master process stops its worker and exits.
  # A process that does not exit in time gets SIGKILL, so no nginx stays
  # behind.
  def stop
    return describe(@status) if @status

    Process.kill(:QUIT, @pid)
    deadline = now + LIMIT
    loop do
      if Process.waitpid(@pid, Process::WNOHANG)
        @status = $?
        return describe(@status)
      end

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
    # A sanitizer build writes its reports to error.log (after nginx has
    # redirected stderr) or to stderr.log (before). Report the first one.
    %w[error.log stderr.log].each do |name|
      path = File.join(@prefix, name)
      next unless File.exist?(path)
      line = File.read(path).split("\n").find { |l| l =~ /runtime error:|AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer/ }
      if line && !@result.key?('sanitizer')
        @result['sanitizer'] = "#{name}: #{line.strip}"
      end
    end
    log = File.join(@prefix, 'error.log')
    return unless @mode != 'http' && File.exist?(log)

    # error.log also holds the source of the session code, so the patterns
    # accept only the characters of a trace or of a result, not "#{".
    m = File.read(log).match(/init trace=\[([a-z_,]*)\]/)
    @result['trace'] = m[1] if m
    m = File.read(log).match(/add_listener in a session: \[([A-Za-z][^\]#]*)\]/)
    @result['add_listener'] = m[1] if m
  end
end

mode = ARGV[0]
unless PORTS.key?(mode)
  puts "error=unknown mode #{mode.inspect}"
  exit 1
end

instance = SecondInstance.new(mode)
instance.run
%w[error reply trace add_listener pp_unknown pp_local pp_none pp_tcp4 pp_values wait_pp wait_plain started quit_seconds worker_signals stdout exit sanitizer].each do |key|
  puts "#{key}=#{instance.result[key]}" if instance.result.key?(key)
end
