# How a content handler that writes no output answers (issue #225): it must
# get a response, 500 with nginx's error page as for Nginx.return
# Nginx::HTTP_OK without output, instead of no response at all.
# Config: test/conf/conf.d/54-content-empty-body.conf (port 18136).

t = SimpleTest.new "ngx_mruby test: a content handler without output"

# Splits a raw response into the status line, the header fields (a Hash
# keyed by the lower-case field name) and the body.
def empty_body_parse(raw)
  head, body = raw.split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  fields = {}
  (lines[1..-1] || []).each do |line|
    name, value = line.split(":", 2)
    next if value.nil?

    fields[name.downcase] = value.strip
  end
  [lines[0].to_s, fields, body.to_s]
end

# One request on its own connection. HTTP/1.0 asks nginx to close the
# connection after the response; HTTP/1.1 without "Connection: close" asks it
# to keep the connection open for the next request.
def empty_body_get(path, method = 'GET', version = '1.0')
  tcp_client(18136, "#{method} #{path} HTTP/#{version}\r\nHost: localhost\r\n\r\n")
end

ERROR_PAGE_TITLE = '<title>500 Internal Server Error</title>'

{
  '/rputs_empty' => 'Nginx.rputs with an empty String',
  '/rputs_nil' => 'Nginx.rputs nil',
  '/headers_only' => 'a handler that only sets a response header',
  '/return_accepted' => 'Nginx.return Nginx::HTTP_ACCEPTED',
  '/sub_request_then_nothing' => 'a handler resumed after Nginx::Async::HTTP.sub_request',
}.each do |path, what|
  t.assert('ngx_mruby - content handler without output', "#{what} without output answers 500") do
    status, raw = empty_body_get(path)
    line, fields, body = empty_body_parse(raw)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
    t.assert_equal 'close', fields['connection']
    t.assert_include body, ERROR_PAGE_TITLE
  end
end

t.assert('ngx_mruby - content handler without output', 'a HEAD request gets the 500 header without a body') do
  status, raw = empty_body_get('/rputs_empty', 'HEAD')
  line, _fields, body = empty_body_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_equal '', body
end

# A request that gets no response leaves a keep-alive connection open until
# keepalive_timeout (75 seconds by default), so tcp_client gives up with
# TIMEOUT after its own limit. With the 500, nginx closes the connection.
t.assert('ngx_mruby - content handler without output', 'a keep-alive request gets the 500 and nginx closes the connection') do
  status, raw = empty_body_get('/rputs_empty', 'GET', '1.1')
  line, fields, body = empty_body_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_equal 'close', fields['connection']
  t.assert_include body, ERROR_PAGE_TITLE
end

# The cases below pass before and after the change: they check that it
# leaves these answers as they were.

t.assert('ngx_mruby - content handler without output', 'Nginx.return Nginx::HTTP_OK without output still answers 500') do
  status, raw = empty_body_get('/return_http_ok')
  line, fields, body = empty_body_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_equal 'close', fields['connection']
  t.assert_include body, ERROR_PAGE_TITLE
end

t.assert('ngx_mruby - content handler without output', 'Nginx.return Nginx::HTTP_NO_CONTENT still answers 204 without a body') do
  status, raw = empty_body_get('/return_204')
  line, fields, body = empty_body_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 204 No Content', line
  t.assert_nil fields['content-length']
  t.assert_equal '', body
end

t.assert('ngx_mruby - content handler without output', 'a content handler with output still answers its body') do
  status, raw = empty_body_get('/with_output')
  line, fields, body = empty_body_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal '6', fields['content-length']
  t.assert_equal 'output', body
end

t.assert('ngx_mruby - content handler without output', 'Nginx.redirect to a location that is still waiting gets that location\'s body') do
  status, raw = empty_body_get('/redirect_to_sleeper')
  line, _fields, body = empty_body_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'slept', body
end

t.assert('ngx_mruby - content handler without output', 'a subrequest whose content handler writes nothing still ends without a response body') do
  status, raw = empty_body_get('/sub_request_to_empty')
  line, _fields, body = empty_body_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'status:0 body:', body
end

t.report
