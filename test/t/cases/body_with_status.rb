# How a handler answers when it writes output and then sets a status with
# Nginx.return (section 2.12 of docs/proposals/core-alpha1.md).
# Config: test/conf/conf.d/89-body-with-status.conf (port 18197).
# Hook script: test/html/body_with_status.rb.
#
# The output goes out with the status that the handler set after it, for
# every status from 200 up and in every handler that sends output, with a
# Content-Length that counts the output. The server has an error_page for
# 401, 403, 429 and 500, which does not apply to such a response, as it does
# not to nginx's own "return 401 text". Before the change, nginx dropped the
# output and sent its own page for the status, through that error_page.

t = SimpleTest.new "ngx_mruby test: output followed by a status is sent with that status"

BODY_WITH_STATUS_PORT = 18197

# Sends one request on its own connection (HTTP/1.0, so that nginx closes
# it after the response) and returns the status of the connection, the
# status line, the response headers (names in lowercase) and the body.
def body_with_status_request(method, path)
  status, raw = tcp_client(BODY_WITH_STATUS_PORT, "#{method} #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
  head, body = raw.split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  headers = {}
  (lines[1..-1] || []).each do |line|
    name, value = line.split(':', 2)
    next if value.nil?

    headers[name.downcase] = value.strip
  end
  [status, lines[0].to_s, headers, body.to_s]
end

t.assert('ngx_mruby - body with status', 'a content handler sends its JSON with the 401 it set after it, without the error_page') do
  status, line, headers, body = body_with_status_request('GET', '/content_401')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 401 Unauthorized', line
  t.assert_equal '{"error":"no key"}', body
  t.assert_equal '{"error":"no key"}'.bytesize.to_s, headers['content-length']
  t.assert_equal 'application/json', headers['content-type']
  t.assert_equal 'no key', headers['x-reason']
end

t.assert('ngx_mruby - body with status', 'HEAD of the same location gets the 401 header with the length of the output and no body') do
  status, line, headers, body = body_with_status_request('HEAD', '/content_401')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 401 Unauthorized', line
  t.assert_equal '{"error":"no key"}'.bytesize.to_s, headers['content-length']
  t.assert_equal 'no key', headers['x-reason']
  t.assert_equal '', body
end

{
  '/access_429' => ['an access handler', 'HTTP/1.1 429 Too Many Requests', '{"error":"rate limited"}'],
  # 202 is a status below 300 that the access phase checker got back and
  # finalized without a response before the change
  '/access_202' => ['an access handler', 'HTTP/1.1 202 Accepted', 'accepted in access'],
  '/rewrite_403' => ['a rewrite handler', 'HTTP/1.1 403 Forbidden', '{"error":"rewrite"}'],
  '/server_rewrite_403' => ['a server rewrite handler', 'HTTP/1.1 403 Forbidden', '{"error":"server rewrite"}'],
  '/post_read_403' => ['a post_read handler', 'HTTP/1.1 403 Forbidden', '{"error":"post_read"}'],
}.each do |path, (handler, status_line, output)|
  t.assert('ngx_mruby - body with status', "#{handler} sends its output with the status it set after it (#{path})") do
    status, line, headers, body = body_with_status_request('GET', path)
    t.assert_equal 'EOF', status
    t.assert_equal status_line, line
    t.assert_equal output, body
    t.assert_equal output.bytesize.to_s, headers['content-length']
  end
end

t.assert('ngx_mruby - body with status', 'output followed by 301 is sent with 301, and ngx_mruby adds no Location') do
  status, line, headers, body = body_with_status_request('GET', '/moved')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 301 Moved Permanently', line
  t.assert_equal 'moved without Location', body
  t.assert_nil headers['location']
end

{
  '/no_content' => 'HTTP/1.1 204 No Content',
  '/not_modified' => 'HTTP/1.1 304 Not Modified',
}.each do |path, status_line|
  t.assert('ngx_mruby - body with status', "output followed by #{status_line[9, 3]} gets the header without the output") do
    status, line, _headers, body = body_with_status_request('GET', path)
    t.assert_equal 'EOF', status
    t.assert_equal status_line, line
    t.assert_equal '', body
  end
end

t.assert('ngx_mruby - body with status', 'output followed by 101 answers 500 without the output') do
  status, line, _headers, body = body_with_status_request('GET', '/switching_protocols')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_false body.include?('not sent with 101')
end

t.assert('ngx_mruby - body with status', 'a subrequest sends its output with the 403 it set after it, and its parent reads both') do
  status, line, _headers, body = body_with_status_request('GET', '/sub_request')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'status:403 body:sub forbidden', body
end

# Passes before and after the change: the way back to nginx's page.
t.assert('ngx_mruby - body with status', 'the status without output still gets nginx\'s answer through the error_page') do
  status, line, _headers, body = body_with_status_request('GET', '/status_only')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 401 Unauthorized', line
  t.assert_equal 'from error_page', body
end

t.report
