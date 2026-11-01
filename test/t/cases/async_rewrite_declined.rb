# A rewrite handler that returns Nginx::DECLINED after Nginx::Async.sleep,
# followed by an access handler that sets no status.
# Config: test/conf/conf.d/82-async-rewrite-declined.conf (port 18187).

t = SimpleTest.new "ngx_mruby test: a rewrite handler that declines after Nginx::Async.sleep"

def async_rewrite_declined_split(raw)
  head, body = raw.split("\r\n\r\n", 2)
  [head.to_s.split("\r\n")[0].to_s, body.to_s]
end

t.assert('async', 'a rewrite handler that declines after the sleep lets the content handler answer 200 with its body') do
  status, raw = tcp_client(18187, "GET /declined_then_content HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_rewrite_declined_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'ok', body
end

t.assert('async', 'a rewrite handler that declines after the sleep lets nginx serve the static file with 200') do
  status, raw = tcp_client(18187, "GET /async_rewrite_declined.txt HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_rewrite_declined_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal "static after a rewrite handler that declined\n", body
end

t.report
