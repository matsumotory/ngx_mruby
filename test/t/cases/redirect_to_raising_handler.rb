# Nginx.redirect to a location whose mruby handler or filter raises.
# Config: test/conf/conf.d/80-redirect-to-raising-handler.conf (port 18134).

t = SimpleTest.new "ngx_mruby test: Nginx.redirect to a handler that raises"

def redirect_raise_split(raw)
  head, body = raw.split("\r\n\r\n", 2)
  [head.to_s.split("\r\n")[0].to_s, body.to_s]
end

# Active connections of the nginx worker (stub_status counts all of them),
# without the one of this request. Connections that earlier tests kept alive
# may close between two calls, so the cases check that the count did not
# grow, not that it stayed the same.
def redirect_raise_active
  res = HttpRequest.new.get base(18134) + '/status'
  res["body"].split("\n")[0].split(":")[1].strip.to_i - 1
end

%w(/redirect_to_raising_content /sleep_then_redirect_to_raising_content /redirect_to_raising_rewrite).each do |path|
  t.assert('redirect', "#{path}: 500, and nginx closes the connection") do
    before = redirect_raise_active
    status, raw = tcp_client(18134, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
    line, body = redirect_raise_split(raw)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
    after = redirect_raise_active
    t.assert_true after <= before, "active connections grew from #{before} to #{after}"
  end
end

t.assert('redirect', '/redirect_to_raising_filter: nginx closes the connection') do
  before = redirect_raise_active
  status, raw = tcp_client(18134, "GET /redirect_to_raising_filter HTTP/1.0\r\nHost: localhost\r\n\r\n")
  t.assert_equal 'EOF', status
  after = redirect_raise_active
  t.assert_true after <= before, "active connections grew from #{before} to #{after}"
end

t.report
