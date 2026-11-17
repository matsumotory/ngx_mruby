# Headers that Nginx::Headers_in#[]= adds before proxy_pass. Config:
# test/conf/conf.d/74-headers-in-proxy.conf (ports 18099 and 18100).
#
# A header that []= adds has its lowcase_key and next set. With
# proxy_headers_hash_bucket_size 1024 in the fragment, nginx's proxy module
# compares each added header with the names of the headers that it sets
# itself, so it leaves out the script's X-Set-By-Proxy, which
# proxy_set_header sets, and sends X-Added-Header on to the upstream on
# 18100, which answers with the headers it received.

t = SimpleTest.new "ngx_mruby test: headers added by Headers_in#[]= through proxy_pass"

# One HTTP/1.0 request on its own connection with exactly the given header
# lines. Returns the connection status, the status line and the body.
def headers_in_proxy(path, headers)
  req = "GET #{path} HTTP/1.0\r\n" + headers.map { |line| "#{line}\r\n" }.join + "\r\n"
  status, raw = tcp_client(18099, req)
  head, body = raw.to_s.split("\r\n\r\n", 2)
  [status, head.to_s.split("\r\n").first.to_s, body.to_s]
end

t.assert('headers_in proxy - X-Added-Header reaches the upstream, and X-Set-By-Proxy has the value of proxy_set_header only', 'GET /add on 18099') do
  status, status_line, body = headers_in_proxy('/add', ['Host: localhost'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal "set_by_proxy=proxy added=script only=\n", body
end

t.assert('headers_in proxy - the same after the script deleted the only header of the request', 'GET /delete_then_add on 18099') do
  status, status_line, body = headers_in_proxy('/delete_then_add', ['X-Only: 1'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal "set_by_proxy=proxy added=script only=\n", body
end

t.report
