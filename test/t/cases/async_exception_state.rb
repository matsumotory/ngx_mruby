# How a request ends when a handler resumed by Nginx::Async.sleep or
# Nginx::Async::HTTP.sub_request raises or calls Nginx.return with a status
# after Nginx.redirect, and when Nginx::Async::HTTP.sub_request requests a
# location whose own handler sleeps.
# Config: test/conf/conf.d/53-async-exception-state.conf (port 18130).

t = SimpleTest.new "ngx_mruby test: how a request ends after Nginx::Async resumes its handler"

def async_exception_split(raw)
  head, body = raw.split("\r\n\r\n", 2)
  [head.to_s.split("\r\n")[0].to_s, body.to_s]
end

t.assert('async', 'an exception after Nginx::Async.sleep answers 500 to that request only') do
  status, raw = tcp_client(18130, "GET /raise_after_sleep HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_exception_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line

  status, raw = tcp_client(18130, "GET /plain HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_exception_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'plain', body
end

t.assert('async', 'an exception after Nginx::Async::HTTP.sub_request answers 500 to that request only') do
  status, raw = tcp_client(18130, "GET /raise_after_sub_request HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_exception_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line

  status, raw = tcp_client(18130, "GET /plain HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_exception_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'plain', body
end

t.assert('async', 'an exception after Nginx.rputs in a resumed handler answers 500 without that output') do
  status, raw = tcp_client(18130, "GET /rputs_then_raise_after_sleep HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_exception_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_include body, '<title>500 Internal Server Error</title>'
  t.assert_not_include body, 'partial'

  status, raw = tcp_client(18130, "GET /plain HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_exception_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'plain', body
end

t.assert('async', 'an exception after Nginx.redirect in a resumed handler ends the request after the redirect target answered') do
  status, raw = tcp_client(18130, "GET /redirect_then_raise_after_sleep HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_exception_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'plain', body

  status, raw = tcp_client(18130, "GET /plain HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_exception_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'plain', body
end

t.assert('async', 'Nginx.return with a status after Nginx.redirect in a resumed handler ends the request after the redirect target answered') do
  status, raw = tcp_client(18130, "GET /redirect_then_return_after_sleep HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_exception_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'plain', body
end

t.assert('async', 'Nginx::Async::HTTP.sub_request to a location whose handler sleeps answers with the response of that location') do
  status, raw = tcp_client(18130, "GET /sub_request_to_sleeper HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_exception_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'got:200:slept', body
end

t.report
