# Nginx.redirect with a local URI raises a RuntimeError in mruby_set handlers
# and in header and body filters, and in Ruby code of a phase handler that
# runs outside the fiber of the handler, and makes no internal redirect: the
# request is answered by its own location, not by the target, whose content
# handler waits. A redirect with a URL keeps working in a filter. The case
# of a log handler is in log_before_access_log.rb.
# Config: test/conf/conf.d/99-redirect-nested.conf (port 18126).
#
# A request is sent with HTTP/1.0, and tcp_client returns when nginx closed
# the connection.

t = SimpleTest.new "ngx_mruby test: Nginx.redirect with a local URI inside another mruby call"

def redirect_nested_error_log
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

# Sends GET path and returns [what tcp_client returned, status line, headers
# (lower-case names), body, error.log lines of the request].
def redirect_nested_get(path)
  offset = File.size(redirect_nested_error_log)
  status, raw = tcp_client(18126, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
  head, body = raw.to_s.split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  headers = {}
  lines[1..-1].to_a.each do |l|
    name, value = l.split(':', 2)
    headers[name.downcase] = value.to_s.strip
  end
  errors = File.open(redirect_nested_error_log) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
  [status, lines[0].to_s, headers, body.to_s, errors]
end

t.assert('redirect nested', 'the target answers a request of its own after its wait') do
  status, line, _headers, body, _errors = redirect_nested_get('/target')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'target', body
end

t.assert('redirect nested', 'an mruby_set handler gets the RuntimeError, its variable is empty and its location answers') do
  status, line, _headers, body, errors = redirect_nested_get('/set')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'value=', body
  raised = errors.select do |l|
    l.include?('#<RuntimeError: Nginx.redirect with a local URI is not available in an mruby_set handler>')
  end
  t.assert_equal 1, raised.size
end

[
  ['/header_filter', 'a header filter'],
  ['/body_filter', 'a body filter'],
].each do |path, where|
  t.assert('redirect nested', "#{where} gets the RuntimeError, and the response of its location is sent") do
    status, line, headers, body, _errors = redirect_nested_get(path)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal "RuntimeError: Nginx.redirect with a local URI is not available in #{where}",
                   headers['x-redirect-nested']
    t.assert_equal 'body', body
  end
end

t.assert('redirect nested', 'the inspect of an exception of a content handler gets the RuntimeError, and the request gets 500') do
  status, line, _headers, body, errors = redirect_nested_get('/inspect')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_not_equal 'target', body
  t.assert_equal 1, errors.select { |l| l.include?('#<RedirectNestedInspect> (inspect raised RuntimeError)') }.size
  t.assert_equal [], errors.select { |l| l.include?('redirect nested: inspect went on 42') }
end

t.assert('redirect nested', 'a redirect with a URL in a header filter sets Location and the status') do
  status, line, headers, body, _errors = redirect_nested_get('/header_filter_url')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 302 Moved Temporarily', line
  t.assert_equal 'http://example.com/redirected', headers['location']
  t.assert_equal 'body', body
end

t.report
