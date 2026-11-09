# How a handler answers when it writes output and then sets a status with
# Nginx.return (section 2.12 of docs/proposals/core-alpha1.md).
# Config: test/conf/conf.d/89-body-with-status.conf (port 18197).
# Hook script: test/html/body_with_status.rb.
#
# The output goes out with the status that the handler set before or after
# it, for every status from 200 up and in every handler that sends output, with a
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

# nginx's header filter removes Content-Length for 204 but not for 304, as
# for its own "return 304 text": the 304 keeps the length of the output.
t.assert('ngx_mruby - body with status', 'output followed by 304 keeps the Content-Length of the output') do
  _status, _line, headers, _body = body_with_status_request('GET', '/not_modified')
  t.assert_equal 'not sent with 304'.bytesize.to_s, headers['content-length']
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

# After Nginx::Async::HTTP.sub_request resumed the handler, which then ends
# from the call of its handler that nginx makes again, the output goes out
# with the status from 300 up that the handler set after it.
{
  '/resumed_access_429' => ['an access handler', 'HTTP/1.1 429 Too Many Requests', 'rate limited after sub ok'],
  '/resumed_content_301' => ['a content handler', 'HTTP/1.1 301 Moved Permanently', 'moved after sub ok'],
}.each do |path, (handler, status_line, output)|
  t.assert('ngx_mruby - body with status', "#{handler} resumed after a subrequest sends its output with the status it set after it (#{path})") do
    status, line, headers, body = body_with_status_request('GET', path)
    t.assert_equal 'EOF', status
    t.assert_equal status_line, line
    t.assert_equal output, body
    t.assert_equal output.bytesize.to_s, headers['content-length']
  end
end

# A status set before the first output is sent with the output as well
# (decision 6 of docs/proposals/core-alpha1.md), with the same rule as a
# status set after it.
t.assert('ngx_mruby - body with status', 'Nginx.status_code = 401 before the output sends the JSON with 401, without the error_page') do
  status, line, headers, body = body_with_status_request('GET', '/before_content_401')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 401 Unauthorized', line
  t.assert_equal '{"error":"status first"}', body
  t.assert_equal '{"error":"status first"}'.bytesize.to_s, headers['content-length']
  t.assert_equal 'application/json', headers['content-type']
end

{
  '/before_access_429' => ['Nginx.return in an access handler', 'HTTP/1.1 429 Too Many Requests', '{"error":"rate limited first"}'],
  '/before_rewrite_403' => ['Nginx.send_header in a rewrite handler', 'HTTP/1.1 403 Forbidden', '{"error":"forbidden first"}'],
  '/before_resumed_rewrite_403' => ['Nginx.status_code= in a rewrite handler that a subrequest then resumes', 'HTTP/1.1 403 Forbidden', 'forbidden after sub ok'],
  # Passes before and after the change: 200 is the status the output had.
  '/before_access_200' => ['Nginx.return Nginx::HTTP_OK in an access handler', 'HTTP/1.1 200 OK', 'ok in access'],
  # Passes before and after the change: the status set after the output
  # replaces the one set before it.
  '/before_then_after' => ['a status before the output and another after it', 'HTTP/1.1 403 Forbidden', 'the later status wins'],
}.each do |path, (what, status_line, output)|
  t.assert('ngx_mruby - body with status', "#{what} sends the output with the status set last (#{path})") do
    status, line, headers, body = body_with_status_request('GET', path)
    t.assert_equal 'EOF', status
    t.assert_equal status_line, line
    t.assert_equal output, body
    t.assert_equal output.bytesize.to_s, headers['content-length']
  end
end

t.assert('ngx_mruby - body with status', '101 before the output answers 500 without the output') do
  status, line, _headers, body = body_with_status_request('GET', '/before_switching_protocols')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_false body.include?('not sent with 101')
end

t.assert('ngx_mruby - body with status', 'a subrequest that sets 202 before its output sends the output with 202') do
  status, line, _headers, body = body_with_status_request('GET', '/before_sub_request')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'status:202 body:sub accepted', body
end

# Nginx::HTTP_CLOSE (444) is nginx's value for closing the connection
# without a response, not a status: with output before or after it, the
# output is not sent and the client gets no byte (decision 7 of
# docs/proposals/core-alpha1.md).
{
  '/close_after_output' => 'a content handler that writes output and then sets 444',
  '/access_close_after_output' => 'an access handler that writes output and then sets 444',
  '/before_close' => 'a content handler that sets 444 and then writes output',
}.each do |path, what|
  t.assert('ngx_mruby - body with status', "#{what} closes the connection without a response (#{path})") do
    status, raw = tcp_client(BODY_WITH_STATUS_PORT, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
    t.assert_true %w[EOF RESET].include?(status), "connection status #{status}"
    t.assert_equal '', raw
  end
end

# Passes before and after the change: the way back to nginx's page.
t.assert('ngx_mruby - body with status', 'the status without output still gets nginx\'s answer through the error_page') do
  status, line, _headers, body = body_with_status_request('GET', '/status_only')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 401 Unauthorized', line
  t.assert_equal 'from error_page', body
end

t.report
