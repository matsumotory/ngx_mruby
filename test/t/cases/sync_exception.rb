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

# Returns the status of the connection, the status line, the header fields
# (names in lower case) and the body.
def sync_exception_response(path)
  status, raw = tcp_client(18143, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
  head, body = raw.split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  fields = {}
  lines[1..-1].to_a.each do |l|
    name, value = l.split(':', 2)
    fields[name.downcase] = value.to_s.strip
  end
  [status, lines[0].to_s, fields, body.to_s]
end

[
  ['/set_rputs_then_raise', 'an exception after Nginx.rputs in an mruby_set handler'],
  ['/set_raise', 'an exception without output in an mruby_set handler'],
  ['/set_after_set_rputs_then_raise', 'an exception after Nginx.rputs in an mruby_set handler after a set directive'],
].each do |path, what|
  t.assert('sync exception', "#{what} sets the variable to an empty string and leaves the length of the response right") do
    status, line, fields, body = sync_exception_response(path)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal '[""]', body
    t.assert_equal body.bytesize.to_s, fields['content-length']
  end
end

# The status line is the one that nginx sends after an exception in an
# output header filter; this test checks the length and the body.
t.assert('sync exception', 'an exception after Nginx.rputs in an output header filter leaves the length of the response right') do
  status, line, fields, body = sync_exception_response('/header_filter_rputs_then_raise')
  t.assert_equal 'EOF', status
  t.assert_equal 'origin', body
  t.assert_equal '6', fields['content-length']
end

t.report
