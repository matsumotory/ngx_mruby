# The mruby log handlers run before access_log: access_log writes the
# variables that they set, and the status that was sent, also when a log
# handler raised or set a status, and Nginx.redirect with a local URI raises
# in a log handler.
# Config: test/conf/conf.d/87-log-before-access-log.conf (port 18195).
#
# A request is sent with HTTP/1.0, and tcp_client returns when nginx closed
# the connection. nginx runs the log phase before it closes the connection,
# so the line of the request is in the access log by then. The log format
# is "$request_uri $status $log_value".

t = SimpleTest.new "ngx_mruby test: log handlers before access_log"

def log_before_access_log_path(name)
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', name)
end

def log_before_access_log_size(name)
  path = log_before_access_log_path(name)
  File.exist?(path) ? File.size(path) : 0
end

# The lines that nginx appended to the log file after offset.
def log_before_access_log_lines(name, offset)
  path = log_before_access_log_path(name)
  return [] unless File.exist?(path)

  File.open(path) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
end

# Sends GET path and returns [status line, body, access log lines of the
# request, error.log lines of the request].
def log_before_access_log_get(path)
  access_offset = log_before_access_log_size('log_before_access_log.log')
  error_offset = log_before_access_log_size('error.log')
  status, raw = tcp_client(18195, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
  head, body = raw.split("\r\n\r\n", 2)
  [status, head.to_s.split("\r\n")[0].to_s, body.to_s,
   log_before_access_log_lines('log_before_access_log.log', access_offset),
   log_before_access_log_lines('error.log', error_offset)]
end

[
  ['/assign', 'an inline log handler', 'assign', 'from-ruby'],
  ['/assign_file', 'a file-based log handler', 'assign_file', 'from-file'],
].each do |path, what, body, value|
  t.assert('log handler', "access_log writes the variable that #{what} assigned") do
    status, line, got_body, access, _errors = log_before_access_log_get(path)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal body, got_body
    t.assert_equal ["#{path} 200 #{value}"], access
  end
end

t.assert('log handler', 'a log handler that raises: access_log writes its variable and the status sent, not 500') do
  status, line, body, access, errors = log_before_access_log_get('/raise')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'raise', body
  t.assert_equal ['/raise 200 before-raise'], access
  # error.log also has the code of the handler, at the info level.
  raised = errors.select { |l| l.include?('#<RuntimeError: log handler before access_log raised>') }
  t.assert_equal 1, raised.size
end

t.assert('log handler', 'a log handler that sets a status: access_log writes the status sent') do
  status, line, body, access, _errors = log_before_access_log_get('/set_status')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'set_status', body
  t.assert_equal ['/set_status 200 set-status'], access
end

t.assert('log handler', 'Nginx.redirect with a local URI raises in a log handler and makes no internal redirect') do
  status, line, body, access, errors = log_before_access_log_get('/redirect')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'redirect', body
  # one line, of /redirect, with the value from before the call and the
  # status that was sent; no line of /assign
  t.assert_equal ['/redirect 200 before-redirect'], access
  raised = errors.select do |l|
    l.include?('#<RuntimeError: Nginx.redirect with a local URI is not available in a log handler>')
  end
  t.assert_equal 1, raised.size
end

t.assert('log handler', 'a log handler that raises after a 404 of return: access_log writes 404') do
  status, line, body, access, errors = log_before_access_log_get('/raise_404')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 404 Not Found', line
  t.assert_equal 'missing', body
  t.assert_equal ['/raise_404 404 raised-404'], access
  raised = errors.select { |l| l.include?('#<RuntimeError: log handler before access_log raised after 404>') }
  t.assert_equal 1, raised.size
end

t.report
