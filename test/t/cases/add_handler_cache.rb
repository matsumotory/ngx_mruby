# A location with mruby_add_handler on and mruby_cache on serves a script from
# its root. mruby_add_handler builds a fresh mruby code from the request path
# on every request, and mruby_cache must not skip compiling it. Before the fix,
# a cached run left the per-request code uncompiled and nginx terminated the
# worker on a request to a script file under this location; now the script runs
# and the worker stays up.
# Config: test/conf/conf.d/98-add-handler-cache.conf (port 18117).

t = SimpleTest.new "ngx_mruby test: mruby_add_handler on with mruby_cache on runs the script"

ADD_HANDLER_CACHE_PORT = 18117

# Sends GET path over HTTP/1.0 and returns the connection status and the body.
def add_handler_cache_get(path)
  req = "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n"
  status, raw = tcp_client(ADD_HANDLER_CACHE_PORT, req)
  _, body = raw.to_s.split("\r\n\r\n", 2)
  [status, body.to_s]
end

t.assert('add_handler cache', 'a script under mruby_add_handler on + mruby_cache on runs') do
  status, body = add_handler_cache_get('/add_handler_cache.rb')
  t.assert_equal 'EOF', status
  t.assert_equal 'add_handler cache', body
end

# The worker still answers a second request after the first.
t.assert('add_handler cache', 'the server answers a second request') do
  status, body = add_handler_cache_get('/add_handler_cache.rb')
  t.assert_equal 'EOF', status
  t.assert_equal 'add_handler cache', body
end

t.report
