# What Nginx::Upstream.new and Nginx::Upstream#server= accept.
# Config: test/conf/conf.d/81-upstream-server-checks.conf (port 18135).

t = SimpleTest.new "ngx_mruby test: the arguments of Nginx::Upstream"

def upstream_checks_get(path)
  HttpRequest.new.get(base(18135) + path)
end

t.assert('upstream', 'Nginx::Upstream.new finds the upstream whose name is the argument') do
  res = upstream_checks_get('/lookup')
  t.assert_equal 200, res.code
  t.assert_equal '192.0.2.2:80', res['body']
end

t.assert('upstream', 'Nginx::Upstream.new raises for a name that only starts the name of an upstream') do
  res = upstream_checks_get('/lookup_prefix')
  t.assert_equal 200, res.code
  t.assert_equal 'RuntimeError', res['body']
end

t.assert('upstream', 'Nginx::Upstream#server= raises for an upstream with a zone and leaves its server') do
  res = upstream_checks_get('/zone')
  t.assert_equal 200, res.code
  t.assert_equal 'RuntimeError, 192.0.2.3:80', res['body']
end

t.assert('upstream', 'Nginx::Upstream#server= raises TypeError for nil and leaves the server') do
  res = upstream_checks_get('/server_nil')
  t.assert_equal 200, res.code
  t.assert_equal 'TypeError, 192.0.2.2:80', res['body']
end

t.assert('upstream', 'Nginx::Upstream.new raises TypeError for nil') do
  res = upstream_checks_get('/new_nil')
  t.assert_equal 200, res.code
  t.assert_equal 'TypeError', res['body']
end

t.report
