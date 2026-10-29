# Nginx::Async.sleep in a content handler.
# Config: test/conf/conf.d/79-async-sleep-in-content.conf (port 18133).

t = SimpleTest.new "ngx_mruby test: Nginx::Async.sleep in a content handler"

def sleep_in_content_split(raw)
  head, body = raw.split("\r\n\r\n", 2)
  [head.to_s.split("\r\n")[0].to_s, body.to_s]
end

def sleep_in_content_fibers
  HttpRequest.new.get(base(18133) + '/fibers')["body"].to_i
end

fibers_before = sleep_in_content_fibers

t.assert('async', 'a content handler that sleeps answers with its body after the sleep') do
  status, raw = tcp_client(18133, "GET /sleep_in_content HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = sleep_in_content_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'slept', body
end

t.assert('async', 'a content handler that sleeps answers with the status it returns') do
  status, raw = tcp_client(18133, "GET /sleep_then_status HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = sleep_in_content_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 503 Service Temporarily Unavailable', line
end

t.assert('async', 'a content handler that raises after the sleep answers 500 without its output') do
  status, raw = tcp_client(18133, "GET /sleep_then_raise HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = sleep_in_content_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_not_include body, 'not sent'
end

t.assert('async', 'a content handler that sleeps twice answers with the output of both parts') do
  status, raw = tcp_client(18133, "GET /sleep_twice HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = sleep_in_content_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'one,two', body
end

t.assert('async', 'a content handler that sleeps answers on a kept-alive connection, and the next request on it is answered too') do
  status, raw = tcp_client(18133, "GET /sleep_in_content HTTP/1.1\r\nHost: localhost\r\n\r\n" \
                                  "GET /sleep_in_content HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
  t.assert_equal 'EOF', status
  t.assert_equal 2, raw.split('HTTP/1.1 200 OK', -1).size - 1
  t.assert_equal 2, raw.split('slept', -1).size - 1
end

t.assert('async', 'Nginx.redirect to a content handler that sleeps, then a status: no output of the sleeping handler follows the response') do
  status, raw = tcp_client(18133, "GET /redirect_to_sleeping_content_then_status HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = sleep_in_content_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 503 Service Temporarily Unavailable', line
  t.assert_not_include body, 'slept'
end

t.assert('async', 'Nginx::Async::HTTP.sub_request after a sleep in a content handler raises, and the request gets 500') do
  status, raw = tcp_client(18133, "GET /sleep_then_sub_request HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = sleep_in_content_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_not_include body, 'not sent'
end

t.assert('async', 'a subrequest to a content handler that sleeps gets its output') do
  status, raw = tcp_client(18133, "GET /sub_request_to_sleeping_content HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = sleep_in_content_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'got:200:slept', body
end

t.assert('async', 'a content handler that sleeps leaves no fiber in the GC root') do
  3.times { tcp_client(18133, "GET /sleep_in_content HTTP/1.0\r\nHost: localhost\r\n\r\n") }
  t.assert_equal fibers_before, sleep_in_content_fibers
end

t.report
