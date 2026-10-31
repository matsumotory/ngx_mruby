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

{
  'empty' => 'invalid upstream server (empty or too long)',
  'long' => 'invalid upstream server (empty or too long)',
  'port' => 'invalid port in upstream 192.0.2.6:notaport',
  'nohost' => 'no host in upstream :80',
  'ipv6' => 'invalid IPv6 address in upstream [2001:db8::zz]:80',
  'unix' => 'no path in the unix domain socket in upstream unix:',
  'host' => 'upstream server nonexistent.invalid:80 is not an IP address or a unix: path',
  'localhost' => 'upstream server localhost:80 is not an IP address or a unix: path',
  'short' => 'upstream server 127.1:80 is not an IP address or a unix: path'
}.each do |name, message|
  t.assert('upstream', "Nginx::Upstream#server= raises ArgumentError for the string #{name} and leaves the server") do
    res = upstream_checks_get("/server_invalid?#{name}")
    t.assert_equal 200, res.code
    t.assert_equal "ArgumentError, 192.0.2.2:80, #{message}", res['body']
  end
end

t.assert('upstream', 'Nginx::Upstream#server= accepts an IPv4 address with or without a port, an IPv6 address and a unix: path') do
  res = upstream_checks_get('/server_forms')
  t.assert_equal 200, res.code
  t.assert_equal "192.0.2.7:8080\n192.0.2.8\n[2001:db8::1]:8080\nunix:/tmp/mrb_ups_check.sock\n", res['body']
end

t.assert('upstream', 'Nginx::Upstream.new raises TypeError for nil') do
  res = upstream_checks_get('/new_nil')
  t.assert_equal 200, res.code
  t.assert_equal 'TypeError', res['body']
end

t.report
