# Nginx::Headers_in and Nginx::Headers_out (section 2.2 of
# docs/proposals/core-alpha1.md). Config: test/conf/conf.d/74-headers-exact.conf
# (ports 18095, 18097 and 18098). Hook script: test/html/headers_exact.rb.
#
# - delete and []= find every header whose name has the same length and the
#   same bytes in any case, and no other;
# - Headers_out keeps Content-Type, Location, Date and Server in nginx's own
#   fields, so the response has one line of each, and [] reads the field;
# - a name is a String or a Symbol, else TypeError; a value that is not a
#   String is converted with to_s;
# - a header that Headers_in#[]= adds has its lowcase_key and hash set, so
#   nginx's proxy module recognizes a header that proxy_set_header sets and
#   passes on the others.

t = SimpleTest.new "ngx_mruby test: Nginx::Headers_in and Nginx::Headers_out"

# One HTTP/1.0 request on its own connection with exactly the given header
# lines. Returns the connection status, the status line, the header lines
# (an Array of [name, value], names in lower case) and the body.
def headers_exact(port, path, headers = [])
  req = "GET #{path} HTTP/1.0\r\n" + headers.map { |line| "#{line}\r\n" }.join + "\r\n"
  status, raw = tcp_client(port, req)
  head, body = raw.to_s.split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  status_line = lines.shift.to_s
  fields = lines.map do |line|
    name, value = line.split(':', 2)
    [name.to_s.downcase, value.to_s.strip]
  end
  [status, status_line, fields, body.to_s]
end

# The values of the header lines with this name, in order.
def headers_exact_values(fields, name)
  fields.select { |n, _| n == name }.map { |_, v| v }
end

FOO_HEADERS = ['Host: localhost', 'X-Foo: 1', 'X-Foo-Bar: 2', 'X-Foo: 3']

t.assert('headers - Headers_in#delete removes every header of the name and no other', 'GET /in_delete on 18095') do
  status, status_line, _, body = headers_exact(18095, '/in_delete', FOO_HEADERS)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal 'X-Foo=nil X-Foo-Bar="2"', body
end

t.assert('headers - Headers_in#delete with a Symbol in other case', 'GET /in_delete_symbol on 18095') do
  status, status_line, _, body = headers_exact(18095, '/in_delete_symbol', FOO_HEADERS)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal 'X-Foo=nil X-Foo-Bar="2"', body
end

t.assert('headers - Headers_in#[]= replaces every header of the name and no other', 'GET /in_set on 18095') do
  status, status_line, _, body = headers_exact(18095, '/in_set', FOO_HEADERS)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal 'X-Foo="new" X-Foo-Bar="2"', body
end

t.assert('headers - Headers_out#delete removes every header of the name', 'GET /out_delete on 18095') do
  status, status_line, fields, body = headers_exact(18095, '/out_delete', ['Host: localhost'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal [], headers_exact_values(fields, 'x-d')
  t.assert_equal ['kept'], headers_exact_values(fields, 'x-kept')
  t.assert_equal 'X-D=nil', body
end

t.assert('headers - Content-Type set by a handler is sent once and read back', 'GET /content_type on 18095') do
  status, status_line, fields, body = headers_exact(18095, '/content_type', ['Host: localhost'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal ['application/json'], headers_exact_values(fields, 'content-type')
  t.assert_equal 'Content-Type="application/json"', body
end

t.assert('headers - deleting Content-Type clears it', 'GET /content_type_delete on 18095') do
  status, status_line, fields, body = headers_exact(18095, '/content_type_delete', ['Host: localhost'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal [], headers_exact_values(fields, 'content-type')
  t.assert_equal 'Content-Type=nil', body
end

t.assert('headers - a header filter reads and replaces the Content-Type of a static file', 'GET /static_content_type on 18095') do
  status, status_line, fields, body = headers_exact(18095, '/static_content_type', ['Host: localhost'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal ['application/x-headers-exact'], headers_exact_values(fields, 'content-type')
  t.assert_equal ['"text/plain"'], headers_exact_values(fields, 'x-before')
  t.assert_equal File.open(html_path('output_filters_static.txt')) { |f| f.read }, body
end

t.assert('headers - Date set by a handler replaces the Date of nginx', 'GET /date on 18095') do
  status, status_line, fields, body = headers_exact(18095, '/date', ['Host: localhost'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal ['Thu, 01 Jan 2026 00:00:00 GMT'], headers_exact_values(fields, 'date')
  t.assert_equal 'Date="Thu, 01 Jan 2026 00:00:00 GMT"', body
end

t.assert('headers - a Location that starts with a slash is made absolute', 'GET /location_relative on 18095') do
  status, status_line, fields, _ = headers_exact(18095, '/location_relative', ['Host: localhost'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 302 Moved Temporarily', status_line
  t.assert_equal ['http://localhost:18095/headers-exact-target'], headers_exact_values(fields, 'location')
end

t.assert('headers - an absolute Location is sent as it is', 'GET /location_absolute on 18095') do
  status, status_line, fields, _ = headers_exact(18095, '/location_absolute', ['Host: localhost'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 302 Moved Temporarily', status_line
  t.assert_equal ['http://example.com/headers-exact-target'], headers_exact_values(fields, 'location')
end

t.assert('headers - Server named in lower case replaces the Server of nginx', 'GET /server_lower on 18095') do
  status, status_line, fields, body = headers_exact(18095, '/server_lower', ['Host: localhost'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal ['headers-exact'], headers_exact_values(fields, 'server')
  t.assert_equal 'Server="headers-exact"', body
end

t.assert('headers - deleting the Server that a handler set gives the Server of nginx', 'GET /server_delete on 18095') do
  status, status_line, fields, body = headers_exact(18095, '/server_delete', ['Host: localhost'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  servers = headers_exact_values(fields, 'server')
  t.assert_equal 1, servers.size
  t.assert_true servers[0].to_s.start_with?('nginx'), "expected nginx's own Server, got: #{servers.inspect}"
  t.assert_equal 'Server=nil', body
end

t.assert('headers - values that are not Strings are converted with to_s', 'GET /value_to_s on 18095') do
  status, status_line, fields, body = headers_exact(18095, '/value_to_s', ['Host: localhost'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal ['1'], headers_exact_values(fields, 'x-n')
  t.assert_equal ['from-to-s'], headers_exact_values(fields, 'x-object')
  t.assert_equal ['sym_value'], headers_exact_values(fields, 'x-sym-name')
  t.assert_equal ['a', '2'], headers_exact_values(fields, 'x-arr')
  t.assert_equal 'X-In-Sym="3" X-Arr=["a", "2"]', body
end

t.assert('headers - a to_s that raises leaves the header as it was', 'GET /value_to_s_raises on 18095') do
  status, status_line, fields, body = headers_exact(18095, '/value_to_s_raises', ['Host: localhost'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal ['old'], headers_exact_values(fields, 'x-partial')
  t.assert_equal 'RuntimeError: headers-exact-to-s X-Partial="old"', body
end

t.assert('headers - a name that is neither a String nor a Symbol raises TypeError', 'GET /name_types on 18095') do
  status, status_line, _, body = headers_exact(18095, '/name_types', ['Host: localhost'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal 'TypeError,TypeError,TypeError,TypeError,TypeError', body
end

t.assert('headers - Headers_out#[]= with an Integer name answers 500 and logs TypeError', 'GET /name_type_raises on 18095') do
  status, status_line, _, body = headers_exact(18095, '/name_type_raises', ['Host: localhost'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', status_line
  t.assert_false body.include?('not reached')
  logged = []
  File.open(File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')) do |f|
    f.each_line { |line| logged << line if line.include?('mrb_run failed') && line.include?('TypeError') && line.include?('"GET /name_type_raises') }
  end
  t.assert_true logged.size > 0, 'expected a TypeError of /name_type_raises in error.log'
end

# headers_in[]= before proxy_pass: the upstream on 18098 answers with the
# headers it received. X-Set-By-Proxy is set by proxy_set_header as well, so
# the proxy module sends its own value only; X-Added-Header goes through.
t.assert('headers - a header added by Headers_in#[]= reaches the upstream of proxy_pass', 'GET /add on 18097') do
  status, status_line, _, body = headers_exact(18097, '/add', ['Host: localhost'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal "set_by_proxy=proxy added=script only=\n", body
end

t.assert('headers - headers added after deleting every header of the request reach the upstream', 'GET /delete_then_add on 18097') do
  status, status_line, _, body = headers_exact(18097, '/delete_then_add', ['X-Only: 1'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal "set_by_proxy=proxy added=script only=\n", body
end

t.report
