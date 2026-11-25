# Nginx::Headers_out Content-Length on the 2.x line. Setting Content-Length
# through Nginx::Headers_out does not add a second response header line; nginx
# sends its own Content-Length for the response, and the length cannot be
# changed this way. Config: test/conf/conf.d/76-content-length.conf (ports
# 18096 and 18122). Static file: test/html/content_length_static.txt.

t = SimpleTest.new "ngx_mruby test: Nginx::Headers_out Content-Length (2.x)"

# One HTTP/1.0 request on its own connection. Returns [status, status_line,
# fields, body], names in lower case.
def cl_req(port, path)
  req = "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n"
  status, raw = tcp_client(port, req)
  head, body = raw.to_s.split("\r\n\r\n", 2)
  hlines = head.to_s.split("\r\n")
  status_line = hlines.shift.to_s
  fields = hlines.map do |line|
    name, value = line.split(':', 2)
    [name.to_s.downcase, value.to_s.strip]
  end
  [status, status_line, fields, body.to_s]
end

def cl_values(fields, name)
  fields.select { |n, _| n == name }.map { |_, v| v }
end

STATIC = File.open(html_path('content_length_static.txt')) { |f| f.read }

t.assert('content_length 2.x - a content handler sends one Content-Length, the output length', 'GET /cl_set_then_rputs') do
  status, status_line, fields, body = cl_req(18096, '/cl_set_then_rputs')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal ['11'], cl_values(fields, 'content-length')
  t.assert_equal 'hello world', body
end

t.assert('content_length 2.x - a value equal to the output is still sent once', 'GET /cl_set_correct') do
  status, status_line, fields, body = cl_req(18096, '/cl_set_correct')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal ['5'], cl_values(fields, 'content-length')
  t.assert_equal 'hello', body
end

t.assert('content_length 2.x - a header filter value is not sent; nginx keeps its length', 'GET /cl_hf_proxy') do
  status, status_line, fields, body = cl_req(18096, '/cl_hf_proxy')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal [STATIC.bytesize.to_s], cl_values(fields, 'content-length')
  t.assert_equal STATIC, body
end

t.assert('content_length 2.x - delete has no effect on Content-Length', 'GET /cl_hf_proxy_delete') do
  status, status_line, fields, body = cl_req(18096, '/cl_hf_proxy_delete')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal [STATIC.bytesize.to_s], cl_values(fields, 'content-length')
  t.assert_equal STATIC, body
end

t.report
