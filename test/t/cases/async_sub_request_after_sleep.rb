# Nginx::Async::HTTP.sub_request after a handler of the same request has
# waited in Nginx::Async.sleep.
# Config: test/conf/conf.d/84-async-sub-request-after-sleep.conf (port 18190).
#
# Each request must get its whole response: 200, the body of the subrequest
# in X-Leaf and the body of the content handler. Before the fix, the
# subrequest that the request posted after the sleep did not start, and the
# request waited until the client closed the connection; tcp_client gives
# up after 60 seconds and reports TIMEOUT.

t = SimpleTest.new "ngx_mruby test: Nginx::Async::HTTP.sub_request after Nginx::Async.sleep"

# Returns the status of the connection, the status line, the headers as a
# Hash and the body.
def async_sub_request_after_sleep_get(path)
  status, raw = tcp_client(18190, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
  head, body = raw.split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  headers = {}
  lines[1..-1].to_a.each do |line|
    key, value = line.split(": ", 2)
    headers[key] = value
  end
  [status, lines[0].to_s, headers, body.to_s]
end

[
  ['/rewrite_declined_access_sub_request', 'when the rewrite handler declines without a sleep'],
  ['/rewrite_sleep_declined_access_sub_request', 'when the rewrite handler declines after its sleep'],
  ['/rewrite_sleep_then_sub_request', 'when the rewrite handler calls it after its sleep'],
].each do |path, case_name|
  t.assert('async', "the subrequest runs and the content handler answers #{case_name}") do
    status, line, headers, body = async_sub_request_after_sleep_get(path)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal 'leaf', headers['X-Leaf']
    t.assert_equal 'content', body
  end
end

t.report
