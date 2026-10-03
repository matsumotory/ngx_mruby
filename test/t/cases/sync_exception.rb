# How a request ends when a handler calls Nginx.rputs and then raises before
# its fiber ever yields, for each kind of handler that answers the request.
# Config: test/conf/conf.d/63-sync-exception.conf (port 18143).

t = SimpleTest.new "ngx_mruby test: how a request ends after an exception in a handler that did not yield"

# Returns the status of the connection, the status line and the body.
def sync_exception_get(path, host = 'localhost')
  status, raw = tcp_client(18143, "GET #{path} HTTP/1.0\r\nHost: #{host}\r\n\r\n")
  head, body = raw.split("\r\n\r\n", 2)
  [status, head.to_s.split("\r\n")[0].to_s, body.to_s]
end

t.assert('sync exception', 'an exception without output in a content handler answers 500') do
  status, line, body = sync_exception_get('/content_raise')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_include body, '<title>500 Internal Server Error</title>'
end

t.assert('sync exception', 'an exception after Nginx.rputs in a content handler answers 500 without that output') do
  status, line, body = sync_exception_get('/content_rputs_then_raise')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_include body, '<title>500 Internal Server Error</title>'
  t.assert_not_include body, 'partial'
end

t.assert('sync exception', 'an exception after Nginx.rputs in a rewrite handler answers 500 without that output') do
  status, line, body = sync_exception_get('/rewrite_rputs_then_raise')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_include body, '<title>500 Internal Server Error</title>'
  t.assert_not_include body, 'partial'
end

t.assert('sync exception', 'an exception after Nginx.rputs in an access handler answers 500 without that output or the content') do
  status, line, body = sync_exception_get('/access_rputs_then_raise')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_include body, '<title>500 Internal Server Error</title>'
  t.assert_not_include body, 'partial'
  t.assert_not_include body, 'content'
end

t.assert('sync exception', 'an exception after Nginx.rputs in a post-read handler answers 500 without that output or the content') do
  status, line, body = sync_exception_get('/', 'post-read.sync-exception.test')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_include body, '<title>500 Internal Server Error</title>'
  t.assert_not_include body, 'partial'
  t.assert_not_include body, 'content'
end

t.assert('sync exception', 'an exception after Nginx.rputs in a server rewrite handler answers 500 without that output or the content') do
  status, line, body = sync_exception_get('/', 'server-rewrite.sync-exception.test')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_include body, '<title>500 Internal Server Error</title>'
  t.assert_not_include body, 'partial'
  t.assert_not_include body, 'content'
end

t.report
