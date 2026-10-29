# What Nginx::Stream::Connection.new and #upstream_server= accept.
# Config: test/conf/conf.d/stream/45-upstream-server-checks.conf (port 12378).
# The session logs one "stream upstream checks: NAME=RESULT end" line per check.

t = SimpleTest.new "ngx_mruby test: the arguments of Nginx::Stream::Connection"

def stream_checks_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

offset = File.size(stream_checks_log_path)
status, body = tcp_client(12378)
results = {}
File.open(stream_checks_log_path) do |f|
  f.seek(offset)
  f.read.to_s.split("\n").each do |line|
    next unless line.include?('stream upstream checks: ')
    name, value = line.split('stream upstream checks: ', 2)[1].to_s.split(' end', 2)[0].to_s.split('=', 2)
    results[name] = value
  end
end

t.assert('stream upstream', 'the session runs every check and answers') do
  t.assert_equal 'EOF', status
  t.assert_equal 'checked', body
end

t.assert('stream upstream', 'Nginx::Stream::Connection.new finds the upstream whose name is the argument') do
  t.assert_equal '192.0.2.12:80', results['lookup']
end

t.assert('stream upstream', 'Nginx::Stream::Connection.new raises for a name that only starts the name of an upstream') do
  t.assert_equal 'RuntimeError', results['lookup_prefix']
end

t.assert('stream upstream', '#upstream_server= raises for an upstream with a zone and leaves its server') do
  t.assert_equal 'RuntimeError, 192.0.2.13:80', results['zone']
end

t.assert('stream upstream', '#upstream_server= raises TypeError for nil and leaves the server') do
  t.assert_equal 'TypeError, 192.0.2.12:80', results['server_nil']
end

t.assert('stream upstream', 'Nginx::Stream::Connection.new raises TypeError for nil') do
  t.assert_equal 'TypeError', results['new_nil']
end

t.report
