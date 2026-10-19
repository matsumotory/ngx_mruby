# How a content handler answers when it writes output and then sets a status
# below 300 other than 200, 201 and 204: it must get a response, its output
# with the status it set, instead of no response at all.
# Config: test/conf/conf.d/68-output-then-status.conf (port 18154).
# Hook script: test/html/output_then_status.rb.

t = SimpleTest.new "ngx_mruby test: a content handler that writes output and then sets a status"

# Splits a raw response into the status line, the header fields (a Hash
# keyed by the lower-case field name) and the rest of the bytes.
def output_status_parse(raw)
  head, rest = raw.split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  fields = {}
  (lines[1..-1] || []).each do |line|
    name, value = line.split(":", 2)
    next if value.nil?

    fields[name.downcase] = value.strip
  end
  [lines[0].to_s, fields, rest.to_s]
end

# One request on its own connection. HTTP/1.0 asks nginx to close the
# connection after the response.
def output_status_get(path)
  tcp_client(18154, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
end

{
  '/accepted' => ['Nginx.rputs, then Nginx.return Nginx::HTTP_ACCEPTED', 'HTTP/1.1 202 Accepted', 'accepted'],
  # nginx has no reason phrase for 203 and for a status below 200, and sends
  # the number with a space, as for its own "return 203 text".
  '/echo_then_status_code_203' => ['Nginx.echo, then Nginx.status_code = 203', 'HTTP/1.1 203 ', "non-authoritative\n"],
  '/send_header_partial_content' => ['Nginx.rputs, then Nginx.send_header Nginx::HTTP_PARTIAL_CONTENT', 'HTTP/1.1 206 Partial Content', 'partial'],
  '/continue' => ['Nginx.rputs, then Nginx.return Nginx::HTTP_CONTINUE', 'HTTP/1.1 100 ', 'continue'],
  # 0 is no status: the output gets 200, as output without a status does.
  '/zero' => ['Nginx.rputs, then Nginx.return 0', 'HTTP/1.1 200 OK', 'zero'],
}.each do |path, (what, status_line, output)|
  t.assert('ngx_mruby - output, then a status', "#{what} answers the output with that status") do
    status, raw = output_status_get(path)
    line, fields, body = output_status_parse(raw)
    t.assert_equal 'EOF', status
    t.assert_equal status_line, line
    t.assert_equal output.bytesize.to_s, fields['content-length']
    t.assert_equal output, body
  end
end

# Two requests on one keep-alive connection, the second with
# "Connection: close". Without a response to the first, nginx goes on with
# the second, so the client gets only the second response. With the fix the
# client gets both, one after the other, and nginx keeps the connection open
# after the first.
t.assert('ngx_mruby - output, then a status', 'a keep-alive connection gets the 202 and then the response to the next request') do
  payload = "GET /accepted HTTP/1.1\r\nHost: localhost\r\n\r\n" \
            "GET /ok HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
  status, raw = tcp_client(18154, payload)
  line, fields, rest = output_status_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 202 Accepted', line
  t.assert_equal 'keep-alive', fields['connection']
  t.assert_equal '8', fields['content-length']
  t.assert_equal 'accepted', rest[0, 8]
  second_line, second_fields, second_body = output_status_parse(rest[8..-1].to_s)
  t.assert_equal 'HTTP/1.1 200 OK', second_line
  t.assert_equal 'close', second_fields['connection']
  t.assert_equal 'ok', second_body
end

# The cases below pass before and after the change: they check that it
# leaves these answers as they were.

t.assert('ngx_mruby - output, then a status', 'Nginx.rputs, then Nginx.return Nginx::HTTP_OK still answers the output with 200') do
  status, raw = output_status_get('/ok')
  line, fields, body = output_status_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal '2', fields['content-length']
  t.assert_equal 'ok', body
end

t.assert('ngx_mruby - output, then a status', 'Nginx.rputs, then Nginx.return Nginx::HTTP_CREATED still answers nginx\'s 201 without the output') do
  status, raw = output_status_get('/created')
  line, fields, body = output_status_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 201 Created', line
  t.assert_equal '0', fields['content-length']
  t.assert_equal '', body
end

t.assert('ngx_mruby - output, then a status', 'Nginx.rputs, then Nginx.return Nginx::HTTP_NOT_FOUND still answers nginx\'s 404 page without the output') do
  status, raw = output_status_get('/not_found')
  line, _fields, body = output_status_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 404 Not Found', line
  t.assert_include body, '<title>404 Not Found</title>'
  t.assert_false body.include?('not found')
end

t.assert('ngx_mruby - output, then a status', 'Nginx.return Nginx::HTTP_ACCEPTED before the first Nginx.rputs still answers the output with 200') do
  status, raw = output_status_get('/status_before_output')
  line, fields, body = output_status_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal '12', fields['content-length']
  t.assert_equal 'status first', body
end

t.assert('ngx_mruby - output, then a status', 'a subrequest whose content handler writes output and sets 202 still ends without a response body') do
  status, raw = output_status_get('/sub_request_to_accepted')
  line, _fields, body = output_status_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'status:0 body:', body
end

t.report
