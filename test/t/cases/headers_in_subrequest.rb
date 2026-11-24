# A script that changes the request's header list in a subrequest and in the
# main request. nginx shares the list between them (ngx_http_subrequest copies
# r->headers_in into the subrequest, so the parts after the embedded first part
# are the same structs), while each keeps its own nalloc and last. Before the
# fix, a change a script made in one request (a delete that advanced a shared
# part, or an add) changed the list the other request then read and forwarded,
# so the other request could forward the wrong headers or lose its own. A
# 40-header request has a second, shared part; the deleted name is at position
# 21, the first of that part. Config:
# test/conf/conf.d/75-headers-in-subrequest.conf. Ports 18106 (handlers) and
# 18109 (the upstream, which reports the headers it received through $http_*).
# Each case asserts the headers the upstream receives.

t = SimpleTest.new "ngx_mruby test: a subrequest and the main request change the shared header list"

# One HTTP/1.0 request on its own connection with exactly the given header
# lines. Returns the connection status and the body.
def hdr_sr(path, headers)
  req = "GET #{path} HTTP/1.0\r\n" + headers.map { |line| "#{line}\r\n" }.join + "\r\n"
  status, raw = tcp_client(18106, req)
  [status, raw.to_s.split("\r\n\r\n", 2)[1].to_s]
end

# 40 headers X-H01..X-H40; the one at position `strip_at` is "X-Strip: s".
def forty(strip_at)
  (1..40).map { |i| i == strip_at ? 'X-Strip: s' : ('X-H%02d: v%02d' % [i, i]) }
end

# (a) auth_request: the subrequest deletes X-Strip, then the main content
# handler adds X-Main-Add. The deleted header is the first of the second part.
t.assert('headers_in subrequest - auth_request deletes then the main adds', 'GET /auth_main on 18106') do
  status, body = hdr_sr('/auth_main', forty(21))
  t.assert_equal 'EOF', status
  t.assert_equal 'main ok', body
end

# (a) async sub_request + proxy_pass: the subrequest deletes X-Strip, the main
# adds X-Main-Add, then the request reaches the upstream. The subrequest changes
# only its own copy of the shared part, so the main request still forwards
# X-Strip (strip=s), together with the main-added header and the other headers.
t.assert('headers_in subrequest - the subrequest deletes but only its own copy, the main adds', 'GET /p_del_add on 18106') do
  status, body = hdr_sr('/p_del_add', forty(21))
  t.assert_equal 'EOF', status
  t.assert_equal "main=main sub= strip=s h01=v01 h22=v22 h40=v40\n", body
end

# (b) the subrequest adds X-Sub-Add, then the main adds X-Main-Add. The
# subrequest's add goes to its own copy, so the main request does not forward it
# (sub=). Nothing is deleted, so X-Strip stays.
t.assert('headers_in subrequest - the subrequest adds to its own copy, the main adds', 'GET /p_subadd_mainadd on 18106') do
  status, body = hdr_sr('/p_subadd_mainadd', forty(21))
  t.assert_equal 'EOF', status
  t.assert_equal "main=main sub= strip=s h01=v01 h22=v22 h40=v40\n", body
end

# (c) the main adds, then the subrequest adds. The subrequest's add does not
# reach the main request (sub=).
t.assert('headers_in subrequest - the main adds, the subrequest adds to its own copy', 'GET /p_mainadd_subadd on 18106') do
  status, body = hdr_sr('/p_mainadd_subadd', forty(21))
  t.assert_equal 'EOF', status
  t.assert_equal "main=main sub= strip=s h01=v01 h22=v22 h40=v40\n", body
end

# (d) the main deletes X-Strip, then the subrequest adds X-Sub-Add. The main's
# own delete reaches the upstream (strip=); the subrequest's add does not (sub=).
t.assert('headers_in subrequest - the main deletes, the subrequest adds to its own copy', 'GET /p_maindel_subadd on 18106') do
  status, body = hdr_sr('/p_maindel_subadd', forty(21))
  t.assert_equal 'EOF', status
  t.assert_equal "main= sub= strip= h01=v01 h22=v22 h40=v40\n", body
end

# (e) the subrequest deletes the whole second part (X-H21..X-H40), emptying it,
# then the main adds and goes to the upstream. Before the fix the emptied part
# stayed on the main request's chain and was forwarded in its place. With the
# fix the subrequest empties only its own copy, so the main request forwards
# X-H01..X-H40 and X-Main-Add.
t.assert('headers_in subrequest - the subrequest empties a shared part in its own copy, the main forwards all', 'GET /p_emptypart on 18106') do
  headers = (1..40).map { |i| 'X-H%02d: v%02d' % [i, i] }
  status, body = hdr_sr('/p_emptypart', headers)
  t.assert_equal 'EOF', status
  t.assert_equal "main=main sub= strip= h01=v01 h22=v22 h40=v40\n", body
end

# (e2) the subrequest empties the whole second part, then the main request
# forwards without changing its own headers. This isolates the forwarding path,
# with no add: before the fix the emptied part stayed on the main request's
# chain and was forwarded in place of its headers, so the main request lost
# X-H21..X-H40 (h22= h40=). The lost headers are the reliable signal this case
# asserts. With the fix the subrequest empties only its own copy, so the main
# request forwards all of X-H01..X-H40 (h22=v22 h40=v40).
t.assert('headers_in subrequest - the subrequest empties a shared part, the main forwards unchanged', 'GET /p_emptyread on 18106') do
  headers = (1..40).map { |i| 'X-H%02d: v%02d' % [i, i] }
  status, body = hdr_sr('/p_emptyread', headers)
  t.assert_equal 'EOF', status
  t.assert_equal "main= sub= strip= h01=v01 h22=v22 h40=v40\n", body
end

# (f) 20 headers or fewer, so the list has only the embedded part. That part is
# a separate struct in each request (ngx_http_subrequest copies it by value), so
# the subrequest's delete of X-Strip does not reach the main request, which
# still forwards X-Strip (strip=s). The main adds X-Main-Add. This is unchanged
# from before the fix: the embedded part is never shared, so the add there uses
# ngx_list_push as it did.
t.assert('headers_in subrequest - the embedded part only (a small request)', 'GET /p_small on 18106') do
  status, body = hdr_sr('/p_small', ['X-H01: v01', 'X-H02: v02', 'X-Strip: s', 'X-H04: v04', 'X-H05: v05'])
  t.assert_equal 'EOF', status
  t.assert_equal "main=main sub= strip=s h01=v01 h22= h40=\n", body
end

# (g) 20 headers or fewer (the embedded part only): the main adds X-Main-Add,
# then an async subrequest adds X-Sub-Add. The main request forwards its own
# added header (main=main) and not the subrequest's (sub=): the subrequest is
# made after the main's add, so it copies the longer list and adds past it,
# leaving the main's slot alone.
t.assert('headers_in subrequest - the embedded part only, the main adds then the subrequest adds', 'GET /p_doubleadd on 18106') do
  status, body = hdr_sr('/p_doubleadd', ['X-H01: v01', 'X-H02: v02', 'X-Strip: s', 'X-H04: v04', 'X-H05: v05'])
  t.assert_equal 'EOF', status
  t.assert_equal "main=main sub= strip=s h01=v01 h22= h40=\n", body
end

t.report
