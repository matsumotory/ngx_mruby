t = SimpleTest.new "ngx_mruby test: stream (ports 12353 to 12358)"

# The servers on ports 12353 to 12356 and 12358 are in
# test/conf/conf.d/stream/40-stream.conf. tcp_client, nginx_t and
# second_instance are in test/t/cases/_prelude.rb. The second nginx of
# test/t/cases/_second_instance.rb listens on port 12357.

def proxy_v1_line(family, src, dst, port)
  "PROXY #{family} #{src} #{dst} 40000 #{port}\r\n"
end

# characterizes v2 behaviour; see docs/proposals/v3-plan.md
# nginx accepts both mruby_stream_init_code and mruby_stream_init in one
# stream block. The later directive replaces the earlier one without a
# message, so only the later hook runs. nginx -t runs the init hook, and its
# p line shows which one ran.
t.assert('ngx_mruby - stream init, the later of the inline and the file version runs', 'nginx -t') do
  inline = %q{mruby_stream_init_code 'p "mruby_stream_init_code"';}
  file = "mruby_stream_init #{html_path('stream_init.rb')};"

  out = nginx_t("stream {\n#{inline}\n#{file}\n}")
  t.assert_include out, 'test is successful'
  t.assert_include out, '"mruby_stream_init file"'
  t.assert_not_include out, '"mruby_stream_init_code"'

  out = nginx_t("stream {\n#{file}\n#{inline}\n}")
  t.assert_include out, 'test is successful'
  t.assert_include out, '"mruby_stream_init_code"'
  t.assert_not_include out, '"mruby_stream_init file"'
end

if under_valgrind?
  puts 'stream: the second nginx is not started under valgrind'
else
  # characterizes v2 behaviour; see docs/proposals/v3-plan.md
  # The second nginx has each inline *_code hook followed by its file version.
  # The trace shows the order: the server context code while nginx reads the
  # configuration, then the init file, then the init_worker file. The p lines
  # show that none of the inline hooks ran and that the exit_worker file ran
  # when nginx stopped.
  t.assert('ngx_mruby - stream init, init_worker and exit_worker files in a second nginx', '127.0.0.1:12357') do
    r = second_instance('stream')
    t.assert_nil r['error']
    t.assert_equal 'stream session ok', r['reply']
    t.assert_equal 'server_context_code,init_file,init_worker_file', r['trace']
    t.assert_equal '"mruby_stream_init file"|"mruby_stream_init_worker file"|"mruby_stream_exit_worker file"', r['stdout']
    t.assert_equal 'exited 0', r['exit']
  end
end

t.assert('ngx_mruby - stream proxy_protocol_addr and proxy_protocol_ip, IPv4', '127.0.0.1:12354') do
  res = tcp_client(12354, proxy_v1_line("TCP4", "192.0.2.10", "127.0.0.1", 12354))
  t.assert_equal ["EOF", "proxy_protocol ok 192.0.2.10"], res
end

t.assert('ngx_mruby - stream proxy_protocol_addr and proxy_protocol_ip, IPv6', '127.0.0.1:12353') do
  res = tcp_client(12353, proxy_v1_line("TCP6", "2001:db8::1", "2001:db8::2", 12353))
  t.assert_equal ["EOF", "proxy_protocol ok 2001:db8::1"], res
end

t.assert('ngx_mruby - stream proxy_protocol_addr decides the session', '127.0.0.1:12354') do
  # The code sets ABORT for an address it does not expect on the port, and
  # nginx closes the connection without sending anything.
  res = tcp_client(12354, proxy_v1_line("TCP4", "198.51.100.7", "127.0.0.1", 12354))
  t.assert_equal ["EOF", ""], res
end

t.assert('ngx_mruby - stream Nginx::Stream::ABORT closes the connection', '127.0.0.1:12355') do
  # The backend of port 12355 answers as soon as a client connects, so a
  # session that is not aborted would end with its text.
  t.assert_equal ["EOF", "backend answered"], tcp_client(12358)
  t.assert_equal ["EOF", ""], tcp_client(12355)
end

t.assert('ngx_mruby - stream instance stream_status and stream_status=', '127.0.0.1:12356 added by add_listener') do
  t.assert_equal ["EOF", "instance stream_status ok"], tcp_client(12356)
end

t.report
