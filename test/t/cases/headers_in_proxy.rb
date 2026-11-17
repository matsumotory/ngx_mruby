# Headers that Nginx::Headers_in#[]= adds before proxy_pass. Config:
# test/conf/conf.d/74-headers-in-proxy.conf (ports 18099 and 18100).
#
# A header that []= adds has its lowcase_key and next set, so nginx's proxy
# module compares it with the names of the headers it sets (here
# X-Set-By-Proxy of proxy_set_header) and sends the other headers on to the
# upstream on 18100, which answers with the headers it received.

t = SimpleTest.new "ngx_mruby test: headers added by Headers_in#[]= through proxy_pass"

# One HTTP/1.0 request on its own connection with exactly the given header
# lines. Returns the connection status, the status line and the body.
def headers_in_proxy(path, headers)
  req = "GET #{path} HTTP/1.0\r\n" + headers.map { |line| "#{line}\r\n" }.join + "\r\n"
  status, raw = tcp_client(18099, req)
  head, body = raw.to_s.split("\r\n\r\n", 2)
  [status, head.to_s.split("\r\n").first.to_s, body.to_s]
end

t.assert('headers_in proxy - a header added by Headers_in#[]= reaches the upstream of proxy_pass', 'GET /add on 18099') do
  status, status_line, body = headers_in_proxy('/add', ['Host: localhost'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal "set_by_proxy=proxy added=script only=\n", body
end

t.assert('headers_in proxy - headers added after deleting every header of the request reach the upstream', 'GET /delete_then_add on 18099') do
  status, status_line, body = headers_in_proxy('/delete_then_add', ['X-Only: 1'])
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', status_line
  t.assert_equal "set_by_proxy=proxy added=script only=\n", body
end

t.report
