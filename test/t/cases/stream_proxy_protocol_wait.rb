# The PROXY protocol header of a stream session, proxy_protocol_addr on a
# connection without a PROXY source address, and stream sessions that wait
# when worker_shutdown_timeout expires. Config:
# test/conf/conf.d/stream/48-proxy-protocol-wait.conf (port 12384), and the
# mode stream_master of test/t/cases/_second_instance.rb (ports 12385 to
# 12388), a second nginx with a master process and one worker. tcp_client and
# second_instance are in test/t/cases/_prelude.rb.

t = SimpleTest.new "ngx_mruby test: the PROXY protocol header and stream sessions that wait"

def pp_line(src, port)
  "PROXY TCP4 #{src} 127.0.0.1 #{port} 12384\r\n"
end

# The client sends bytes during the sleep, and the case checks the reply after
# the sleep. nginx does not read the bytes before the return directive ends
# the session. On Linux, a socket closed
# with bytes that it has not read sends a reset, so the client may see RESET
# after the reply instead of EOF; the reply is what the case checks.
t.assert('ngx_mruby - stream proxy_protocol: bytes during the sleep (1), the reply after the sleep', '127.0.0.1:12384') do
  status, body = tcp_client(12384, pp_line('192.0.2.10', 40000), pp_line('192.0.2.99', 40001))
  t.assert_include ['EOF', 'RESET'], status
  t.assert_equal 'pp 192.0.2.10:40000', body
end

t.assert('ngx_mruby - stream proxy_protocol: bytes during the sleep (2), the reply after the sleep', '127.0.0.1:12384') do
  status, body = tcp_client(12384, pp_line('192.0.2.10', 40000), "hello\r\n")
  t.assert_include ['EOF', 'RESET'], status
  t.assert_equal 'pp 192.0.2.10:40000', body
end

master = second_instance('stream_master')
if master['sanitizer'] || master['error']
  puts File.read(File.join(ENV['NGINX_INSTALL_DIR'], 'second_instance', 'stream_master', 'error.log'))
end

# The code of port 12385 (proxy_protocol) and 12386 (without it) reads
# proxy_protocol_addr and proxy_protocol_ip with the class and the instance
# methods. The session goes on when the four values agree.
t.assert('ngx_mruby - stream proxy_protocol_addr is nil without a PROXY source address', '127.0.0.1:12385 and 12386') do
  t.assert_nil master['error']
  t.assert_equal 'pp ', master['pp_unknown']
  t.assert_equal 'pp ', master['pp_local']
  t.assert_equal 'pp ', master['pp_none']
  t.assert_equal 'pp 192.0.2.10', master['pp_tcp4']
  t.assert_equal ['[nil, nil, nil, nil]'] * 3 + ['["192.0.2.10", "192.0.2.10", "192.0.2.10", "192.0.2.10"]'],
                 master['pp_values'].to_s.split('|')
  t.assert_equal '0', master['worker_signals']
end

# Ports 12387 (proxy_protocol) and 12388 (without it): the code sleeps 10
# seconds, and the script sends SIGQUIT with worker_shutdown_timeout 1s. The
# sessions end when the timeout expires, without the text of the return
# directive, and the code of each started once.
t.assert('ngx_mruby - stream sessions that sleep end at worker_shutdown_timeout', '127.0.0.1:12387 and 12388') do
  t.assert_nil master['error']
  t.assert_true master['quit_seconds'].to_f < 5.0, "nginx exited #{master['quit_seconds']} seconds after SIGQUIT"
  t.assert_equal '', master['wait_pp']
  t.assert_equal '', master['wait_plain']
  t.assert_equal '2', master['started']
end

t.assert('ngx_mruby - stream the second nginx with a master process stops without a sanitizer report', '127.0.0.1:12385 to 12388') do
  t.assert_nil master['sanitizer']
  t.assert_equal 'exited 0', master['exit']
end

t.report
