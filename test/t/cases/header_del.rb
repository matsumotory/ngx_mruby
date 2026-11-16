# ngx_mrb_del_request_header deletes a request header. Config:
# test/conf/conf.d/73-header-del.conf (port 18105). Hook script:
# test/html/header_del.rb.
#
# The function walks the ngx_list of headers and removes the first whose name
# matches. Before the fix it (a) compared only key_len bytes, so a name that
# is a prefix of a header matched and deleted that header, and the compare read
# past a shorter key; (b) split a full part around the removed element and left
# headers->last pointing inside that part's array, so the next ngx_list_push
# wrote one element past its end; and (c) adopted the next part when the first
# part emptied without moving headers->last, so a header added afterwards was
# written into the detached part and was not visible. The fix removes the
# element by moving the rest of the part down, compares the length first, and
# keeps headers->last in step.

t = SimpleTest.new "ngx_mruby test: delete a request header"

# One HTTP/1.0 request on its own connection with the given header lines, so
# the request carries exactly these headers in r->headers_in.headers. Returns
# the connection status and the response body.
def header_del(path, headers)
  req = "GET #{path} HTTP/1.0\r\n" + headers.map { |line| "#{line}\r\n" }.join + "\r\n"
  status, raw = tcp_client(18105, req)
  [status, raw.to_s.split("\r\n\r\n", 2)[1].to_s]
end

t.assert('header delete - a name that is a prefix of a header does not delete the header', 'GET /prefix on 18105') do
  status, body = header_del('/prefix', ['X-Prefix-Match: keep'])
  t.assert_equal 'EOF', status
  t.assert_equal 'match:keep', body
end

t.assert('header delete - emptying the full first part keeps a header added next', 'GET /empty-first on 18105') do
  headers = (1..21).map { |n| 'X-A%02d: %d' % [n, n] }
  status, body = header_del('/empty-first', headers)
  t.assert_equal 'EOF', status
  t.assert_equal 'last:last', body
end

t.assert('header delete - deleting from the middle of a full part then adding headers', 'GET /overflow on 18105') do
  headers = (1..20).map { |n| 'X-B%02d: %d' % [n, n] }
  status, body = header_del('/overflow', headers)
  t.assert_equal 'EOF', status
  t.assert_equal 'overflow:19', body
end

# $http_user_agent reads r->headers_in.user_agent, the pointer nginx cached to
# the User-Agent element. Deleting X-B, which comes before User-Agent (and
# User-Agent is followed by X-C), must leave that pointer on the same element.
# A delete that moved the elements would make $http_user_agent read X-C.
t.assert('header delete - a deleted header keeps a later header cached pointer ($http_user_agent)', 'GET /cache-ptr on 18105') do
  headers = ['X-A: a', 'X-B: b', 'User-Agent: UA-MARK', 'X-C: c']
  status, body = header_del('/cache-ptr', headers)
  t.assert_equal 'EOF', status
  t.assert_equal 'ua:UA-MARK', body
end

t.report
