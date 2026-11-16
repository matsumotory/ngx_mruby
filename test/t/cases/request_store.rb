# Nginx::Request#store: one Hash for every handler of a request, kept across
# an internal redirect, a store of its own for a subrequest, and no slot of
# the GC root holder left after the request (section 2.1 of
# docs/proposals/core-alpha1.md).
# Config: test/conf/conf.d/99-request-store.conf (port 18094).
#
# A request is sent with HTTP/1.0, and tcp_client returns when nginx closed
# the connection, after the log phase and after the request pool was
# destroyed.

t = SimpleTest.new "ngx_mruby test: Nginx::Request#store"

def request_store_log
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'request_store.error.log')
end

def request_store_log_lines
  return [] unless File.exist?(request_store_log)

  File.read(request_store_log).split("\n")
end

# Sends GET path and returns [connection status, status line, headers, body].
def request_store_get(path)
  status, raw = tcp_client(18094, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
  head, body = raw.split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  headers = {}
  (lines[1..-1] || []).each do |line|
    key, value = line.split(": ", 2)
    headers[key] = value
  end
  [status, lines[0].to_s, headers, body.to_s]
end

t.assert('Nginx::Request#store', 'the store of the access handler reaches @next after error_page') do
  logged = request_store_log_lines.count { |l| l.include?('request_store log: key=from-access') }
  status, line, headers, body = request_store_get('/redirect')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'key=from-access set=set same=true', body
  t.assert_equal 'from-access', headers['X-Store']
  t.assert_equal logged + 1, request_store_log_lines.count { |l| l.include?('request_store log: key=from-access') }
end

t.assert('Nginx::Request#store', 'a subrequest gets an empty store of its own') do
  status, line, _headers, body = request_store_get('/sub')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'leaf=sub=true empty=true main=main', body
end

t.assert('Nginx::Request#store', 'the stores leave no object in the GC root holder') do
  before = request_store_get('/stats')
  request_store_get('/redirect')
  request_store_get('/sub')
  after = request_store_get('/stats')
  [before, after].each do |result|
    t.assert_equal 'EOF', result[0]
    t.assert_equal 'HTTP/1.1 200 OK', result[1]
  end
  # reject an absent counter instead of reading it as zero
  count = before[3].split('=', 2)[1].to_s
  t.assert_equal true, before[3].start_with?('gc_root=') && !count.empty? && count == count.to_i.to_s
  t.assert_equal before[3], after[3]
end

t.report
