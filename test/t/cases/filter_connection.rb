# Nginx::Filter#output, Nginx::Upstream#keepalive_cache= and
# Nginx::Connection (including a listener with proxy_protocol).
# Server config: test/conf/conf.d/20-filter-connection.conf (ports 58112, 58113).
# Raw socket client: test/t/cases/_filter_connection_client.rb (CRuby).

t = SimpleTest.new "ngx_mruby test: filter, upstream keepalive_cache, connection"

def connection_client(mode)
  `ruby ./test/t/cases/_filter_connection_client.rb #{mode}`.chomp
end

# Nginx::Filter#output

# Most filter locations use the return directive as the origin, so the body
# filter sees a response with a known Content-Length.

t.assert('ngx_mruby - Filter#output', 'returns the stored byte length and a second call replaces the body') do
  res = HttpRequest.new.get base(58112) + '/filter/output_return'
  t.assert_equal 200, res.code
  t.assert_equal 'hello|5', res["body"]
  t.assert_equal '7', res["content-length"]
end

t.assert('ngx_mruby - Filter#output', 'body read in the filter is the origin response') do
  res = HttpRequest.new.get base(58112) + '/filter/output_from_body'
  t.assert_equal 'nigiro!', res["body"]
  t.assert_equal '7', res["content-length"]
end

t.assert('ngx_mruby - Filter#output', 'a non-String argument is converted with to_s') do
  res = HttpRequest.new.get base(58112) + '/filter/output_non_string'
  t.assert_equal '12345', res["body"]
  t.assert_equal '5', res["content-length"]
end

# characterizes v2 behaviour; see docs/proposals/v3-plan.md on the next branch
# Filter#output with an empty String makes the body filter pass a zero size
# last buffer, nginx rejects it, and the connection is closed before the
# status line is written. The client receives no byte.
t.assert('ngx_mruby - Filter#output', 'an empty String closes the connection without a response') do
  t.assert_equal '<closed>', connection_client('filter_empty')
end

t.assert('ngx_mruby - Filter#output', 'the returned length counts bytes, not characters') do
  res = HttpRequest.new.get base(58112) + '/filter/output_multibyte'
  t.assert_equal "\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86|9", res["body"]
  t.assert_equal '11', res["content-length"]
end

t.assert('ngx_mruby - Filter#output', 'the body can grow beyond the origin length') do
  res = HttpRequest.new.get base(58112) + '/filter/output_grow'
  t.assert_equal 'a' * 10000, res["body"]
  t.assert_equal '10000', res["content-length"]
end

t.assert('ngx_mruby - Filter#output', 'mruby_output_body_filter with a file hook') do
  res = HttpRequest.new.get base(58112) + '/filter/output_file'
  t.assert_equal 'file: origin', res["body"]
  t.assert_equal '12', res["content-length"]
end

t.assert('ngx_mruby - Filter#output', 'filters a proxied response') do
  res = HttpRequest.new.get base(58112) + '/filter/output_proxy'
  t.assert_equal 'proxied: backend body', res["body"]
  t.assert_equal '21', res["content-length"]
end

# characterizes v2 behaviour; see docs/proposals/v3-plan.md on the next branch
# When the origin is an mruby content handler (Nginx.rputs) in the same
# location, the response keeps the origin Content-Length, so a longer body set
# with Filter#output is cut to the origin length.
t.assert('ngx_mruby - Filter#output', 'with an Nginx.rputs origin the origin length is kept') do
  res = HttpRequest.new.get base(58112) + '/filter/output_rputs_origin'
  t.assert_equal 200, res.code
  t.assert_equal '[origi', res["body"]
  t.assert_equal '6', res["content-length"]
end

t.assert('ngx_mruby - Filter#body', 'outside a body filter returns an empty String') do
  res = HttpRequest.new.get base(58112) + '/filter/body_in_content'
  t.assert_equal '""', res["body"]
end

# Nginx::Upstream#keepalive_cache and keepalive_cache=

t.assert('ngx_mruby - Upstream#keepalive_cache', 'returns the mruby_upstream_keepalive value') do
  res = HttpRequest.new.get base(58112) + '/upstream/configured'
  t.assert_equal '4|127.0.0.1:58112', res["body"]
end

t.assert('ngx_mruby - Upstream#keepalive_cache', 'is 1 when mruby_upstream_keepalive is absent') do
  res = HttpRequest.new.get base(58112) + '/upstream/no_directive'
  t.assert_equal '1', res["body"]
end

t.assert('ngx_mruby - Upstream#keepalive_cache=', 'returns the new value and the getter reads it back') do
  res = HttpRequest.new.get base(58112) + '/upstream/set'
  t.assert_equal '3|9|2|2', res["body"]
end

t.assert('ngx_mruby - Upstream#keepalive_cache=', 'values below 2 raise ArgumentError and keep the old value') do
  res = HttpRequest.new.get base(58112) + '/upstream/set_invalid'
  msg = 'ArgumentError: invalid upstream_cache: set value > 1'
  t.assert_equal [msg, msg, msg, '5'].join('|'), res["body"]
end

# characterizes v2 behaviour; see docs/proposals/v3-plan.md on the next branch
# keepalive_cache= writes to the upstream configuration of the worker, so the
# value set in one request is seen by the next request. The test nginx runs a
# single worker, which makes the order of these two requests deterministic.
t.assert('ngx_mruby - Upstream#keepalive_cache=', 'the value persists into later requests') do
  res = HttpRequest.new.get base(58112) + '/upstream/persist_get'
  t.assert_equal '2', res["body"]
  res = HttpRequest.new.get base(58112) + '/upstream/persist_set'
  t.assert_equal '6', res["body"]
  res = HttpRequest.new.get base(58112) + '/upstream/persist_get'
  t.assert_equal '6', res["body"]
end

t.assert('ngx_mruby - Upstream#keepalive_cache=', 'proxying through the upstream still works after the change') do
  res = HttpRequest.new.get base(58112) + '/upstream/set_then_proxy'
  t.assert_equal 200, res.code
  t.assert_equal 'backend body', res["body"]
  t.assert_equal '5', res["x-keepalive-cache"]
end

# The keepalive_cache= cases above leave the values that they set in the
# worker. This case puts back the values from
# test/conf/conf.d/20-filter-connection.conf, so that a second run against the
# same nginx starts from them.
t.assert('ngx_mruby - Upstream#keepalive_cache=', 'puts back the configured values') do
  res = HttpRequest.new.get base(58112) + '/upstream/restore'
  t.assert_equal '3|2|2', res["body"]
end

# characterizes v2 behaviour; see docs/proposals/v3-plan.md on the next branch
# Upstream.new compares the given name case-insensitively and only over the
# length of the given name, so a prefix selects the first matching upstream.
t.assert('ngx_mruby - Upstream.new', 'matches a prefix of the name and ignores case') do
  res = HttpRequest.new.get base(58112) + '/upstream/name_match'
  t.assert_equal '7|4', res["body"]
end

t.assert('ngx_mruby - Upstream.new', 'an unknown name raises RuntimeError') do
  res = HttpRequest.new.get base(58112) + '/upstream/unknown'
  t.assert_equal 'RuntimeError: keepalive_cache_nothing not found upstream config', res["body"]
end

# Nginx::Connection

t.assert('ngx_mruby - Connection', 'remote_ip, local_ip and local_port on a plain listener') do
  res = HttpRequest.new.get base(58112) + '/connection/info'
  t.assert_equal '127.0.0.1|127.0.0.1|58112|String|String', res["body"]
end

t.assert('ngx_mruby - Connection#remote_port', 'is the source port of the client socket') do
  port, body = connection_client('remote_port').split('|', 2)
  t.assert_true port.to_i > 0
  t.assert_equal port, body
end

# On a listener with proxy_protocol, Connection#remote_ip and #local_ip keep
# the TCP peer addresses (no realip module), and the addresses from the PROXY
# header are visible through Nginx::Var.
t.assert('ngx_mruby - Connection with proxy_protocol', 'PROXY v1 TCP4') do
  t.assert_equal '127.0.0.1|127.0.0.1|58113|"192.0.2.10"|"40000"|"192.0.2.20"|"8443"', connection_client('pp_v1_tcp4')
end

t.assert('ngx_mruby - Connection with proxy_protocol', 'PROXY v1 TCP6') do
  t.assert_equal '127.0.0.1|127.0.0.1|58113|"2001:db8::1"|"40001"|"2001:db8::2"|"443"', connection_client('pp_v1_tcp6')
end

t.assert('ngx_mruby - Connection with proxy_protocol', 'PROXY v2 TCP4') do
  t.assert_equal '127.0.0.1|127.0.0.1|58113|"192.0.2.30"|"40002"|"192.0.2.40"|"9443"', connection_client('pp_v2_tcp4')
end

t.assert('ngx_mruby - Connection with proxy_protocol', 'PROXY UNKNOWN') do
  t.assert_equal '127.0.0.1|127.0.0.1|58113|nil|nil|nil|nil', connection_client('pp_v1_unknown')
end

t.assert('ngx_mruby - Connection with proxy_protocol', 'a request without a PROXY header is closed') do
  t.assert_equal '<closed>', connection_client('pp_none')
end

t.report
