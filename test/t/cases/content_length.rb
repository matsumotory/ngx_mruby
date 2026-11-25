# Nginx::Headers_out Content-Length (section 2.2 of docs/proposals/core-alpha1.md
# and the 3.0.0 release notes). Config: test/conf/conf.d/76-content-length.conf
# (ports 18096 and 18122). Static file: test/html/content_length_static.txt.
#
# []= sets nginx's own Content-Length field, and ngx_http_mruby_header_filter
# reconciles the length a script sets with the body nginx frames before the
# headers go out:
# - a handler that writes output sends the output's length (a warn names a
#   value that differs); a value with no output is Content-Length: 0;
# - a value that is not a non-negative decimal raises ArgumentError;
# - [] returns the value set, or the length nginx knows;
# - a header or phase handler on a proxied or static response sends the real
#   length (a warn names a value that differs), or the response chunked when
#   that length is not known;
# - #delete sends the response chunked;
# - 204 sends no Content-Length.
# So the response carries one Content-Length that matches the body, or is sent
# chunked.

t = SimpleTest.new "ngx_mruby test: Nginx::Headers_out Content-Length"

# One request on its own connection. version "1.0" (the server closes after the
# response) or "1.1" with Connection: close (for a chunked response, which
# HTTP/1.0 does not use). Returns [status, status_line, fields, body], names in
# lower case.
def cl_req(port, path, method: 'GET', version: '1.0')
  lines = ["#{method} #{path} HTTP/#{version}", 'Host: localhost']
  lines << 'Connection: close' if version == '1.1'
  req = lines.map { |l| "#{l}\r\n" }.join + "\r\n"
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

# Decode a chunked body into its bytes.
def cl_dechunk(body)
  out = ''.b
  s = body.to_s.b
  loop do
    nl = s.index("\r\n")
    break if nl.nil?
    size = s[0...nl].to_i(16)
    s = s[(nl + 2)..-1].to_s
    break if size == 0
    out << s[0...size].to_s
    s = s[(size + 2)..-1].to_s
  end
  out
end

# The lines of error.log that name this request path.
def cl_warned?(path)
  found = false
  File.open(File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')) do |f|
    f.each_line do |line|
      found = true if line.include?('does not match the response body') && line.include?(path)
    end
  end
  found
end

def cl_logged_argument_error?(path)
  found = false
  File.open(File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')) do |f|
    f.each_line do |line|
      found = true if line.include?('mrb_run failed') && line.include?('ArgumentError') && line.include?(path)
    end
  end
  found
end

STATIC = File.open(html_path('content_length_static.txt')) { |f| f.read }

t.assert('content_length - a content handler sends the output length, not the set value', 'GET /cl_set_then_rputs') do
  status, status_line, fields, body = cl_req(18096, '/cl_set_then_rputs')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal ['11'], cl_values(fields, 'content-length')
  t.assert_equal 'hello world', body
  t.assert_true cl_warned?('/cl_set_then_rputs'), 'expected a warn for the differing Content-Length'
end

t.assert('content_length - order of []= and rputs does not matter', 'GET /cl_rputs_then_set') do
  status, status_line, fields, body = cl_req(18096, '/cl_rputs_then_set')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal ['11'], cl_values(fields, 'content-length')
  t.assert_equal 'hello world', body
end

t.assert('content_length - a correct length is sent with no warn', 'GET /cl_set_correct') do
  status, status_line, fields, body = cl_req(18096, '/cl_set_correct')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal ['5'], cl_values(fields, 'content-length')
  t.assert_equal 'hello', body
  t.assert_false cl_warned?('/cl_set_correct'), 'expected no warn for a correct Content-Length'
end

t.assert('content_length - a length with no output is Content-Length: 0', 'GET /cl_set_no_output') do
  status, status_line, fields, body = cl_req(18096, '/cl_set_no_output')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal ['0'], cl_values(fields, 'content-length')
  t.assert_equal '', body
end

t.assert('content_length - a non-numeric value raises ArgumentError (500)', 'GET /cl_bad_value') do
  status, status_line, _, body = cl_req(18096, '/cl_bad_value')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', status_line
  t.assert_false body.include?('not reached')
  t.assert_true cl_logged_argument_error?('/cl_bad_value'), 'expected an ArgumentError of /cl_bad_value in error.log'
end

t.assert('content_length - a negative value raises ArgumentError (500)', 'GET /cl_bad_negative') do
  status, status_line, _, _ = cl_req(18096, '/cl_bad_negative')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', status_line
  t.assert_true cl_logged_argument_error?('/cl_bad_negative'), 'expected an ArgumentError of /cl_bad_negative in error.log'
end

t.assert('content_length - an Array of several values raises ArgumentError (500)', 'GET /cl_bad_array') do
  status, status_line, _, _ = cl_req(18096, '/cl_bad_array')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', status_line
  t.assert_true cl_logged_argument_error?('/cl_bad_array'), 'expected an ArgumentError of /cl_bad_array in error.log'
end

t.assert('content_length - [] returns the value the script set', 'GET /cl_read') do
  status, status_line, _, body = cl_req(18096, '/cl_read')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal 'get=7', body
end

t.assert('content_length - a 204 with a set Content-Length sends none', 'GET /cl_204') do
  _, status_line, fields, _ = cl_req(18096, '/cl_204')
  t.assert_equal 'HTTP/1.1 204 No Content', status_line
  t.assert_equal [], cl_values(fields, 'content-length')
end

t.assert('content_length - a phase handler before a static file sends the file length', 'GET /cl_access_static') do
  status, status_line, fields, body = cl_req(18096, '/cl_access_static')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal [STATIC.bytesize.to_s], cl_values(fields, 'content-length')
  t.assert_equal STATIC, body
  t.assert_true cl_warned?('/cl_access_static'), 'expected a warn for the differing Content-Length'
end

t.assert('content_length - a header filter length that differs from a proxied body sends the real length', 'GET /cl_hf_proxy_wrong') do
  status, status_line, fields, body = cl_req(18096, '/cl_hf_proxy_wrong')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal [STATIC.bytesize.to_s], cl_values(fields, 'content-length')
  t.assert_equal STATIC, body
  t.assert_true cl_warned?('/cl_hf_proxy_wrong'), 'expected a warn for the differing Content-Length'
end

t.assert('content_length - [] in a header filter returns the length nginx knows', 'GET /cl_hf_proxy_read') do
  status, status_line, fields, _ = cl_req(18096, '/cl_hf_proxy_read')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal [STATIC.bytesize.to_s], cl_values(fields, 'x-cl')
  t.assert_equal [STATIC.bytesize.to_s], cl_values(fields, 'content-length')
end

t.assert('content_length - a correct header filter length is sent with no warn', 'GET /cl_hf_proxy_correct') do
  status, status_line, fields, body = cl_req(18096, '/cl_hf_proxy_correct')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal [STATIC.bytesize.to_s], cl_values(fields, 'content-length')
  t.assert_equal STATIC, body
  t.assert_false cl_warned?('/cl_hf_proxy_correct'), 'expected no warn for a correct Content-Length'
end

t.assert('content_length - #delete in a header filter sends the response chunked', 'GET /cl_hf_proxy_delete') do
  status, status_line, fields, body = cl_req(18096, '/cl_hf_proxy_delete', version: '1.1')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal [], cl_values(fields, 'content-length')
  t.assert_equal ['chunked'], cl_values(fields, 'transfer-encoding')
  t.assert_equal STATIC, cl_dechunk(body)
end

t.assert('content_length - a header filter length on an unknown-length response sends it chunked, not with Content-Length', 'GET /cl_hf_proxy_chunked') do
  status, status_line, fields, body = cl_req(18096, '/cl_hf_proxy_chunked', version: '1.1')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal [], cl_values(fields, 'content-length')
  t.assert_equal ['chunked'], cl_values(fields, 'transfer-encoding')
  t.assert_equal STATIC, cl_dechunk(body)
  t.assert_true cl_warned?('/cl_hf_proxy_chunked'), 'expected a warn for the differing Content-Length'
end

t.assert('content_length - a body filter on an unknown-length response is still sent chunked', 'GET /cl_hf_bf_chunked') do
  status, status_line, fields, body = cl_req(18096, '/cl_hf_bf_chunked', version: '1.1')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal [], cl_values(fields, 'content-length')
  t.assert_equal ['chunked'], cl_values(fields, 'transfer-encoding')
  t.assert_equal STATIC, cl_dechunk(body)
  t.assert_true cl_warned?('/cl_hf_bf_chunked'), 'expected a warn for the differing Content-Length'
end

t.assert('content_length - a 304 with a set Content-Length sends none', 'GET /cl_304') do
  _, status_line, fields, _ = cl_req(18096, '/cl_304')
  t.assert_equal 'HTTP/1.1 304 Not Modified', status_line
  t.assert_equal [], cl_values(fields, 'content-length')
end

t.report
