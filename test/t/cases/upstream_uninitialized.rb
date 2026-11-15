# Nginx::Upstream and Nginx::Stream::Connection objects that hold no
# upstream: one from allocate, one whose initialize raised (no upstream has
# the name, or the upstream has two servers), and one whose second
# initialize raised. Their upstream methods raise ArgumentError, and the
# worker answers the next request or session. An object whose initialize
# succeeds after a failure works.
# Config: test/conf/conf.d/97-upstream-uninitialized.conf (port 18093) and
# test/conf/conf.d/stream/53-upstream-uninitialized.conf (port 12397).

t = SimpleTest.new "ngx_mruby test: upstream objects that hold no upstream"

def uninit_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

# The lines that error.log gets from offset on.
def uninit_lines_from(offset)
  File.open(uninit_log_path) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
end

def uninit_get(path)
  HttpRequest.new.get(base(18093) + path)
end

UNINIT_OBJECTS = ['allocate', 'not_found', 'multiple', 'reinit']

UNINIT_OBJECTS.each do |object|
  ['server', 'server_set', 'keepalive_cache', 'keepalive_cache_set'].each do |method|
    t.assert('upstream uninitialized', "Nginx::Upstream (#{object}): #{method} raises ArgumentError, and the worker answers the next request") do
      offset = File.size(uninit_log_path)
      res = uninit_get("/call?#{object}-#{method}")
      t.assert_equal 500, res['code']
      lines = uninit_lines_from(offset).select { |l| l.include?(' [error] ') && l.include?('mrb_run failed') }
      t.assert_equal 1, lines.size
      t.assert_include lines[0].to_s, 'uninitialized Nginx::Upstream (ArgumentError)'
      alive = uninit_get('/alive')
      t.assert_equal 200, alive['code']
      t.assert_equal 'alive', alive['body']
    end
  end
end

t.assert('upstream uninitialized', 'Nginx::Upstream: initialize succeeds after a failed one') do
  res = uninit_get('/recover')
  t.assert_equal 200, res['code']
  t.assert_equal '192.0.2.31:80', res['body']
end

# The stream session logs one "stream upstream uninitialized: NAME=RESULT end"
# line per check.
def uninit_stream_session
  offset = File.size(uninit_log_path)
  status, body = tcp_client(12397)
  results = {}
  uninit_lines_from(offset).each do |line|
    next unless line.include?('stream upstream uninitialized: ')
    name, value = line.split('stream upstream uninitialized: ', 2)[1].to_s.split(' end', 2)[0].to_s.split('=', 2)
    results[name] = value
  end
  [status, body, results]
end

status, body, results = uninit_stream_session

t.assert('stream upstream uninitialized', 'the session runs every check and answers') do
  t.assert_equal 'EOF', status
  t.assert_equal 'checked', body
end

UNINIT_OBJECTS.each do |object|
  ['upstream_server', 'upstream_server_set'].each do |method|
    t.assert('stream upstream uninitialized', "Nginx::Stream::Connection (#{object}): #{method} raises ArgumentError") do
      t.assert_equal 'ArgumentError, uninitialized Nginx::Stream::Connection', results["#{object}-#{method}"]
    end
  end
end

t.assert('stream upstream uninitialized', 'Nginx::Stream::Connection: initialize succeeds after a failed one') do
  t.assert_equal '192.0.2.41:80', results['recover']
end

t.assert('stream upstream uninitialized', 'the worker answers the next session') do
  status2, body2, results2 = uninit_stream_session
  t.assert_equal 'EOF', status2
  t.assert_equal 'checked', body2
  t.assert_equal '192.0.2.41:80', results2['recover']
end

t.report
