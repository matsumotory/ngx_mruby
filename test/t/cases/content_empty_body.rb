# How a content handler that writes no output answers (issues #200, #225).
# On next (v3) it answers as nginx's own "return 200;" does: its status, 200
# when it set none, with Content-Length: 0 and an empty body, and the
# connection stays usable for the next request.
# Config: test/conf/conf.d/54-content-empty-body.conf (port 18136).

t = SimpleTest.new "ngx_mruby test: a content handler without output"

EMPTY_BODY_PORT = 18136

# Splits the bytes that one connection received into responses: for each
# request method in methods, the status line, the header fields (a Hash keyed
# by the lower-case field name) and the body. A body is as long as the
# Content-Length of its response, and empty after a HEAD request; a response
# without Content-Length takes the rest of the bytes. It stops early when the
# bytes hold fewer responses than methods, so the caller can count them.
def empty_body_parse_all(raw, methods)
  responses = []
  rest = raw
  methods.each do |method|
    break unless rest.include?("\r\n\r\n")

    head, rest = rest.split("\r\n\r\n", 2)
    rest = rest.to_s
    lines = head.split("\r\n")
    fields = {}
    (lines[1..-1] || []).each do |line|
      name, value = line.split(":", 2)
      next if value.nil?

      fields[name.downcase] = value.strip
    end
    length = if method == 'HEAD'
               0
             elsif fields['content-length']
               fields['content-length'].to_i
             else
               rest.size
             end
    responses << [lines[0].to_s, fields, rest[0, length].to_s]
    rest = rest[length..-1].to_s
  end
  responses
end

def empty_body_parse(raw, method = 'GET')
  empty_body_parse_all(raw, [method])[0] || ['', {}, '']
end

def empty_body_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

# Lines that nginx appended to error.log after offset.
def empty_body_log_lines(offset)
  File.open(empty_body_log_path) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
end

# One request on its own connection, with HTTP/1.0, after which nginx closes
# the connection. It also returns the lines that nginx wrote to error.log
# meanwhile.
def empty_body_get(path, method = 'GET')
  offset = File.size(empty_body_log_path)
  status, raw = tcp_client(EMPTY_BODY_PORT, "#{method} #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
  [status, raw, empty_body_log_lines(offset)]
end

# Two HTTP/1.1 requests sent at once on one keep-alive connection: the
# request under test, then GET /with_output with "Connection: close". Both
# responses arrive only when nginx keeps the connection after the first one.
def empty_body_keepalive(path, method = 'GET')
  payload = "#{method} #{path} HTTP/1.1\r\nHost: localhost\r\n\r\n" +
            "GET /with_output HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
  status, raw = tcp_client(EMPTY_BODY_PORT, payload)
  [status, empty_body_parse_all(raw, [method, 'GET'])]
end

def empty_body_logged(lines)
  lines.select { |l| l.include?('response body is empty') }
end

ERROR_PAGE_TITLE = '<title>500 Internal Server Error</title>'

# path => [what the handler does, the status line, other header fields]
EMPTY_ANSWERS = {
  '/rputs_empty' => ['Nginx.rputs with an empty String', 'HTTP/1.1 200 OK', {}],
  '/rputs_nil' => ['Nginx.rputs nil', 'HTTP/1.1 200 OK', {}],
  '/headers_only' => ['a handler that only sets a response header', 'HTTP/1.1 200 OK', { 'x-empty-body' => 'yes' }],
  '/return_http_ok' => ['Nginx.return Nginx::HTTP_OK', 'HTTP/1.1 200 OK', {}],
  '/return_accepted' => ['Nginx.return Nginx::HTTP_ACCEPTED', 'HTTP/1.1 202 Accepted', {}],
  '/sub_request_then_nothing' => ['a handler resumed after Nginx::Async::HTTP.sub_request', 'HTTP/1.1 200 OK', {}],
  '/sub_request_then_return_ok' => ['Nginx.return Nginx::HTTP_OK after Nginx::Async::HTTP.sub_request', 'HTTP/1.1 200 OK', {}],
  '/empty_with_header_filter' => ['Nginx.return Nginx::HTTP_OK with a header filter', 'HTTP/1.1 200 OK', { 'x-header-filter' => 'ran' }],
}

EMPTY_ANSWERS.each do |path, spec|
  what, status_line, extra = spec
  t.assert('ngx_mruby - content handler without output', "#{what} answers #{status_line[9..-1]} with an empty body") do
    status, raw, lines = empty_body_get(path)
    line, fields, body = empty_body_parse(raw)
    t.assert_equal 'EOF', status
    t.assert_equal status_line, line
    t.assert_equal '0', fields['content-length']
    t.assert_equal '', body
    extra.each { |name, value| t.assert_equal value, fields[name] }
    t.assert_equal [], empty_body_logged(lines)
  end

  t.assert('ngx_mruby - content handler without output', "#{what} keeps a keep-alive connection for the next request") do
    status, responses = empty_body_keepalive(path)
    t.assert_equal 'EOF', status
    t.assert_equal 2, responses.size
    line, fields, body = responses[0] || ['', {}, '']
    t.assert_equal status_line, line
    t.assert_equal '0', fields['content-length']
    t.assert_equal '', body
    next_line, _next_fields, next_body = responses[1] || ['', {}, '']
    t.assert_equal 'HTTP/1.1 200 OK', next_line
    t.assert_equal 'output', next_body
  end
end

t.assert('ngx_mruby - content handler without output', 'a HEAD request gets the 200 header with Content-Length: 0') do
  %w[/return_http_ok /rputs_empty].each do |path|
    status, raw, lines = empty_body_get(path, 'HEAD')
    line, fields, body = empty_body_parse(raw, 'HEAD')
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal '0', fields['content-length']
    t.assert_equal '', body
    t.assert_equal [], empty_body_logged(lines)
  end
end

t.assert('ngx_mruby - content handler without output', 'a HEAD request keeps a keep-alive connection for the next request') do
  status, responses = empty_body_keepalive('/return_http_ok', 'HEAD')
  t.assert_equal 'EOF', status
  t.assert_equal 2, responses.size
  line, fields, body = responses[0] || ['', {}, '']
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal '0', fields['content-length']
  t.assert_equal '', body
  t.assert_equal 'output', (responses[1] || ['', {}, ''])[2]
end

t.assert('ngx_mruby - content handler without output', 'a body filter gets the empty body and its output is sent') do
  status, raw, _lines = empty_body_get('/empty_with_body_filter')
  line, fields, body = empty_body_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal '9', fields['content-length']
  t.assert_equal 'filtered:', body

  status, responses = empty_body_keepalive('/empty_with_body_filter')
  t.assert_equal 'EOF', status
  t.assert_equal 2, responses.size
  t.assert_equal 'filtered:', (responses[0] || ['', {}, ''])[2]
  t.assert_equal 'output', (responses[1] || ['', {}, ''])[2]
end

t.assert('ngx_mruby - content handler without output', 'a body filter that keeps the empty body sends Content-Length: 0') do
  status, raw, lines = empty_body_get('/empty_with_body_filter_unchanged')
  line, fields, body = empty_body_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal '0', fields['content-length']
  t.assert_equal '', body
  t.assert_equal [], lines.select { |l| l.include?('[alert]') }
end

# The cases below pass before and after the change: they check that it
# leaves these answers as they were.

t.assert('ngx_mruby - content handler without output', 'Nginx.return Nginx::HTTP_CREATED still answers 201 with Content-Length: 0') do
  status, raw, _lines = empty_body_get('/return_created')
  line, fields, body = empty_body_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 201 Created', line
  t.assert_equal '0', fields['content-length']
  t.assert_equal '', body

  status, responses = empty_body_keepalive('/return_created')
  t.assert_equal 'EOF', status
  t.assert_equal 2, responses.size
  t.assert_equal 'HTTP/1.1 201 Created', (responses[0] || ['', {}, ''])[0]
  t.assert_equal 'output', (responses[1] || ['', {}, ''])[2]
end

t.assert('ngx_mruby - content handler without output', 'Nginx.return Nginx::HTTP_NO_CONTENT still answers 204 without a body') do
  status, raw, _lines = empty_body_get('/return_204')
  line, fields, body = empty_body_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 204 No Content', line
  t.assert_nil fields['content-length']
  t.assert_equal '', body
end

t.assert('ngx_mruby - content handler without output', 'a status below 200 without output still answers 500') do
  status, raw, lines = empty_body_get('/return_below_200')
  line, fields, body = empty_body_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_equal 'close', fields['connection']
  t.assert_include body, ERROR_PAGE_TITLE
  logged = empty_body_logged(lines).select { |l| l.include?('[error]') && l.include?('status code is 150') }
  t.assert_equal 1, logged.size
end

t.assert('ngx_mruby - content handler without output', 'a content handler with output still answers its body') do
  status, raw, _lines = empty_body_get('/with_output')
  line, fields, body = empty_body_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal '6', fields['content-length']
  t.assert_equal 'output', body
end

t.assert('ngx_mruby - content handler without output', 'Nginx.redirect to a location that is still waiting gets that location\'s body') do
  status, raw, _lines = empty_body_get('/redirect_to_sleeper')
  line, _fields, body = empty_body_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'slept', body
end

t.assert('ngx_mruby - content handler without output', 'a subrequest whose content handler writes nothing still ends without a response body') do
  status, raw, _lines = empty_body_get('/sub_request_to_empty')
  line, _fields, body = empty_body_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'status:0 body:', body
end

t.assert('ngx_mruby - content handler without output', 'Nginx.return Nginx::HTTP_OK without output in a rewrite handler still answers 500') do
  status, raw, lines = empty_body_get('/rewrite_return_ok')
  line, fields, body = empty_body_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_equal 'close', fields['connection']
  t.assert_include body, ERROR_PAGE_TITLE
  logged = empty_body_logged(lines).select { |l| l.include?('[error]') && l.include?('status code is 200') }
  t.assert_equal 1, logged.size
end

t.report
