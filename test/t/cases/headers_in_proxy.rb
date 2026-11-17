# Headers that Nginx::Headers_in#[]= adds before proxy_pass. Config:
# test/conf/conf.d/74-headers-in-proxy.conf (ports 18099 and 18100).
#
# A header that []= adds has its lowcase_key and next set, so that nginx's
# proxy module reads no unset value when it looks the header up among the
# names of the headers that it sets itself (proxy_headers_hash_bucket_size
# 1024 in the fragment makes it compare them). On the 2.x line the added
# header does not match those names, as before: the upstream on 18100,
# which answers with the headers it received, gets every header that the
# script added, X-Set-By-Proxy (also set by proxy_set_header) and
# Keep-Alive (left out of the client's headers by the proxy module)
# included. The cases pass before and after the fix; under valgrind, the
# build before it reports the read of the unset lowcase_key.

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

t.report
