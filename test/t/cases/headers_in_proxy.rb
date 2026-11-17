# Request headers that Nginx::Headers_in#[]= adds or replaces before
# proxy_pass. Config: test/conf/conf.d/74-headers-in-proxy.conf (ports
# 18099 and 18100).
#
# A header that []= adds has its lowcase_key and next set, so that nginx's
# proxy module reads no unset value when it looks the request headers up.
# On the 2.x line an added header is not matched against the names of the
# headers that the proxy module sets: the upstream on 18100, which answers
# with the headers it received, gets every header that the script added,
# wherever the header that the script replaced was in the request. Under
# valgrind, the build before the fix reports the read of the unset
# lowcase_key here.

t = SimpleTest.new "ngx_mruby test: headers added by Headers_in#[]= through proxy_pass"

# One HTTP/1.0 request on its own connection with exactly the given header
# lines. Returns the connection status, the status line and the body.
def headers_in_proxy(path, headers)
  req = "GET #{path} HTTP/1.0\r\n" + headers.map { |line| "#{line}\r\n" }.join + "\r\n"
  status, raw = tcp_client(18099, req)
  head, body = raw.to_s.split("\r\n\r\n", 2)
  [status, head.to_s.split("\r\n").first.to_s, body.to_s]
end

t.assert('headers_in proxy - every header added by Headers_in#[]= reaches the upstream, also one that proxy_set_header sets', 'GET /add on 18099') do
  status, status_line, body = headers_in_proxy('/add', ['Host: localhost'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal "set_by_proxy=proxy, script added=script keep_alive=script x_a=script only=\n", body
end

t.assert('headers_in proxy - the same after the script deleted the only header of the request', 'GET /delete_then_add on 18099') do
  status, status_line, body = headers_in_proxy('/delete_then_add', ['X-Only: 1'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal "set_by_proxy=proxy, script added=script keep_alive=script x_a=script only=\n", body
end

# X-Set-By-Proxy of the client replaced by the script: the upstream gets
# the value of proxy_set_header and that of the script, whether the replaced
# header was followed by another header, was the last header, or was the
# only header of the request.
{
  'followed by another header' => ['Host: localhost', 'X-Set-By-Proxy: client', 'X-After: 1'],
  'the last header' => ['Host: localhost', 'X-Set-By-Proxy: client'],
  'the only header' => ['X-Set-By-Proxy: client'],
}.each do |where, headers|
  t.assert('headers_in proxy - a replaced header reaches the upstream with the value of proxy_set_header', "GET /replace on 18099, the replaced header #{where}") do
    status, status_line, body = headers_in_proxy('/replace', headers)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', status_line
    t.assert_equal "set_by_proxy=proxy, script added= keep_alive= x_a= only=\n", body
  end
end

# Host replaced by the script: the proxy module sends its own Host as well,
# and the upstream (nginx) answers 400 to the two Host lines, whether the
# replaced Host was followed by another header or was the only header.
{
  'followed by another header' => ['Host: localhost', 'X-After: 1'],
  'the only header' => ['Host: localhost'],
}.each do |where, headers|
  t.assert('headers_in proxy - a replaced Host is sent next to the Host of the proxy module', "GET /replace_host on 18099, Host #{where}") do
    status, status_line, _ = headers_in_proxy('/replace_host', headers)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 400 Bad Request', status_line
  end
end

# The value of the script alone: a variable given to proxy_set_header.
t.assert('headers_in proxy - a variable given to proxy_set_header sends the value of the script alone', 'GET /variable on 18099') do
  status, status_line, body = headers_in_proxy('/variable', ['Host: localhost'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal "host=script-host set_by_proxy=script\n", body
end

t.report
