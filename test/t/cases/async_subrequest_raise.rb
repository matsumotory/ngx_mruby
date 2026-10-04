# GC roots of async fibers when Nginx::Async::HTTP.sub_request raises.
# Config: test/conf/conf.d/48-async-subrequest-raise.conf (port 18124).
#
# /fibers on port 18124 counts the live Fiber objects after GC.start. All
# servers of the http block share one mrb_state, so the count also includes
# the fibers of requests to the main server.

t = SimpleTest.new "ngx_mruby test: GC root after a failing async sub request"

def async_raise_split(raw)
  head, body = raw.split("\r\n\r\n", 2)
  [head.to_s.split("\r\n")[0].to_s, body.to_s]
end

def async_raise_fibers
  HttpRequest.new.get(base(18124) + '/fibers')["body"].to_i
end

t.assert('async', 'a sub_request that raises leaves no fiber in the GC root') do
  before = async_raise_fibers
  3.times do
    status, raw = tcp_client(18124, "GET /outer HTTP/1.0\r\nHost: localhost\r\n\r\n")
    line, body = async_raise_split(raw)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal 'outer done', body
  end
  t.assert_equal before, async_raise_fibers
end

# A request to /subrequest_redirect_from on the main server makes a nested
# in-memory sub_request that raises twice: in the rewrite handler of
# /subrequest_redirect_from, and in the rewrite handler of
# /subrequest_redirect_to after the rewrite directive moves the request there.
t.assert('async', 'location /subrequest_redirect_from leaves no fiber in the GC root') do
  before = async_raise_fibers
  3.times do
    res = HttpRequest.new.get base + '/subrequest_redirect_from'
    t.assert_equal 503, res['code']
  end
  t.assert_equal before, async_raise_fibers
end

t.report
