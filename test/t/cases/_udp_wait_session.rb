# Finite UDP session checks in an independent nginx, run with CRuby.
# Ports 12393-12396; at most nine client datagrams per invocation.
require 'socket'
require 'timeout'
require 'json'
require 'fileutils'
require 'tmpdir'

install = File.expand_path(ENV.fetch('NGINX_INSTALL_DIR'))
prefix = Dir.mktmpdir('udp-wait-', File.join(install, 'logs'))
log = File.join(prefix, 'error.log')
conf = File.join(prefix, 'nginx.conf')
module_path = File.join(install, 'modules/ngx_http_mruby_module.so')
head = File.exist?(module_path) ? "load_module #{module_path};\n" : ''
File.write(conf, head + <<~CONF)
  daemon off;
  master_process on;
  worker_processes 1;
  worker_shutdown_timeout 100ms;
  pid #{prefix}/nginx.pid;
  error_log #{log} notice;
  events { worker_connections 64; }
  stream {
    server {
      listen 127.0.0.1:12393 udp;
      mruby_stream_code '
        Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "repeat started"
        Nginx::Stream::Async.sleep 400
        Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "repeat first resumed"
        Nginx::Stream::Async.sleep 400
        Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "repeat second resumed"
      ';
      return "repeat-ok";
    }
    server {
      listen 127.0.0.1:12394 udp;
      mruby_stream_code '
        Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "shutdown started"
        Nginx::Stream::Async.sleep 2000
        Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "shutdown resumed"
      ';
      return "shutdown-ok";
    }
    server {
      listen 127.0.0.1:12395 udp;
      mruby_stream_code '
        Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "proxy started"
        Nginx::Stream::Async.sleep 600
        Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "proxy resumed"
      ';
      proxy_pass 127.0.0.1:12396;
      proxy_timeout 2s;
    }
  }
CONF

read_log = -> { File.exist?(log) ? File.read(log) : '' }
wait_text = ->(text) { Timeout.timeout(3) { sleep 0.01 until read_log.call.include?(text) } }
wait_marker = ->(text) { wait_text.call("#{text} while initializing session") }
counts = ->(labels) { labels.map { |label| read_log.call.scan("#{label} while initializing session").length } }
receive = ->(socket) { IO.select([socket], nil, nil, 3) ? socket.recv(1024) : 'noreply' }
sockets = []
connect = lambda do |port|
  u = UDPSocket.new
  sockets << u
  u.connect('127.0.0.1', port)
  u
end
result = {}
pid = nil
reaped = false
upstream = UDPSocket.new
upstream.bind('127.0.0.1', 12396)
received = []
peers = []
stop_echo = false
echo = Thread.new do
  until stop_echo || received.length >= 8
    next unless IO.select([upstream], nil, nil, 0.1)
    payload, addr = upstream.recvfrom(1024)
    received << payload.unpack1('H*')
    peers << [addr[3], addr[1]]
    upstream.send('echo:'.b + payload, 0, addr[3], addr[1])
  end
end
begin
  Timeout.timeout(20) do
    pid = Process.spawn(File.join(install, 'sbin/nginx'), '-p', prefix + '/', '-c', conf, '-e', log,
                        out: File.join(prefix, 'stdout.log'), err: File.join(prefix, 'stderr.log'))
    wait_text.call('start worker process')
    u = connect.call(12393)
    u.send('one', 0)
    wait_marker.call('repeat started')
    u.send('two', 0)
    wait_marker.call('repeat first resumed')
    u.send('three', 0)
    sleep 0.05
    u.send('four', 0)
    result['repeat_reply'] = receive.call(u)
    result['repeat_counts'] = counts.call(['repeat started', 'repeat first resumed', 'repeat second resumed'])

    p = connect.call(12395)
    first = "first\x00\xffpayload".b
    later = "later\x00\xfepayload".b
    began = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    p.send(first, 0)
    wait_marker.call('proxy started')
    p.send('during-one', 0)
    sleep 0.05
    p.send('during-two', 0)
    result['proxy_first_reply'] = receive.call(p).unpack1('H*')
    result['proxy_first_seconds'] = Process.clock_gettime(Process::CLOCK_MONOTONIC) - began
    p.send(later, 0)
    result['proxy_later_reply'] = receive.call(p).unpack1('H*')
    result['proxy_extra_reply'] = !!IO.select([p], nil, nil, 0.2)
    result['proxy_upstream_payloads'] = received.dup
    result['proxy_upstream_peers'] = peers.uniq.length
    result['proxy_counts'] = counts.call(['proxy started', 'proxy resumed'])

    v = connect.call(12394)
    v.send('shutdown', 0)
    wait_marker.call('shutdown started')
    began = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    Process.kill('QUIT', pid)
    status = nil
    Timeout.timeout(3) { _, status = Process.waitpid2(pid) }
    reaped = true
    result['quit_seconds'] = Process.clock_gettime(Process::CLOCK_MONOTONIC) - began
    result['exit_status'] = status.exitstatus
    result['shutdown_counts'] = counts.call(['shutdown started', 'shutdown resumed'])
    result['runtime_errors'] = read_log.call.lines.count { |line| line.match?(/\[(alert|emerg|crit|error)\]/) }
  end
rescue StandardError => e
  result['error'] = "#{e.class}: #{e.message}"
ensure
  sockets.each(&:close)
  if pid && !reaped
    Process.kill('TERM', pid) rescue nil
    Timeout.timeout(3) { Process.waitpid(pid) } rescue nil
  end
  stop_echo = true
  echo.join(1)
  upstream.close
end
puts JSON.generate(result)
