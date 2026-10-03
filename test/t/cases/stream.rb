t = SimpleTest.new "ngx_mruby test: stream (ports 12353 to 12356)"

# The servers are in test/conf/conf.d/stream/40-stream.conf. The raw client
# test/t/cases/_stream_client.rb runs with CRuby and returns the status of the
# connection (EOF, RESET, REFUSED or TIMEOUT) and the exact bytes received.
def g4_stream(port, payload = "")
  out = `ruby test/t/cases/_stream_client.rb #{port} #{payload.unpack("H*")[0]}`
  status, hex = out.split(":", 2)
  [status, [hex.to_s].pack("H*")]
end

def g4_proxy_v1(family, src, dst, port)
  "PROXY #{family} #{src} #{dst} 40000 #{port}\r\n"
end

t.assert('ngx_mruby - stream init and init_worker files', '127.0.0.1:12353') do
  # The inline mruby_stream_init_code and mruby_stream_init_worker_code would
  # add init_code and init_worker_code to the trace. They do not run, because
  # the file directives after them replace them. This characterizes v2
  # behaviour; see docs/proposals/v3-plan.md.
  t.assert_equal ["EOF", "g4 trace server_context_code,init_file,init_worker_file"], g4_stream(12353)
end

t.assert('ngx_mruby - stream proxy_protocol_addr and proxy_protocol_ip, IPv4', '127.0.0.1:12354') do
  res = g4_stream(12354, g4_proxy_v1("TCP4", "192.0.2.10", "127.0.0.1", 12354))
  t.assert_equal ["EOF", "g4 proxy_protocol ok 192.0.2.10"], res
end

t.assert('ngx_mruby - stream proxy_protocol_addr and proxy_protocol_ip, IPv6', '127.0.0.1:12354') do
  res = g4_stream(12354, g4_proxy_v1("TCP6", "2001:db8::1", "2001:db8::2", 12354))
  t.assert_equal ["EOF", "g4 proxy_protocol ok 2001:db8::1"], res
end

t.assert('ngx_mruby - stream proxy_protocol_addr decides the session', '127.0.0.1:12354') do
  # The code sets ABORT for an address it does not expect, and nginx closes
  # the connection without sending anything.
  res = g4_stream(12354, g4_proxy_v1("TCP4", "198.51.100.7", "127.0.0.1", 12354))
  t.assert_equal ["EOF", ""], res
end

t.assert('ngx_mruby - stream raw client reads a proxied response', '127.0.0.1:12348 (control for the ABORT case)') do
  status, body = g4_stream(12348, "GET /mruby HTTP/1.0\r\n\r\n")
  t.assert_equal "EOF", status
  t.assert_equal "Hello ngx_mruby world!", body.split("\r\n\r\n", 2)[1]
end

t.assert('ngx_mruby - stream Nginx::Stream::ABORT closes the connection', '127.0.0.1:12355') do
  # The client sends nothing. Without ABORT, nginx would connect to
  # g4_backend and the client would wait until its deadline (TIMEOUT).
  t.assert_equal ["EOF", ""], g4_stream(12355)
end

t.assert('ngx_mruby - stream instance stream_status and stream_status=', '127.0.0.1:12356 added by add_listener') do
  t.assert_equal ["EOF", "g4 instance stream_status ok"], g4_stream(12356)
end

t.report
