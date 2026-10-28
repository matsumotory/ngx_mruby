# Nginx::Upstream#server= keeps the round-robin peer valid for a later
# request. Config: test/conf/conf.d/70-upstream-server.conf (port 18159).
# /set sets the server to 127.0.0.1:18161 (the upstream block names
# 127.0.0.1:18160), and /get, a separate request, reads it back. The peer is
# shared and lives for the worker's life, so the address that /set stored must
# still be readable in /get.

t = SimpleTest.new "ngx_mruby test: Nginx::Upstream#server= across requests"

t.assert('ngx_mruby - Upstream#server= then read it in a later request', 'GET /set then /get on 18159') do
  r1 = HttpRequest.new.get base(18159) + '/set'
  t.assert_equal 200, r1.code
  t.assert_equal 'set', r1['body']

  # A separate request reads the peer that /set changed. Its name and address
  # must point at worker-lifetime storage, not the freed request pool of /set.
  r2 = HttpRequest.new.get base(18159) + '/get'
  t.assert_equal 200, r2.code
  t.assert_equal '127.0.0.1:18161', r2['body']
end

t.report
