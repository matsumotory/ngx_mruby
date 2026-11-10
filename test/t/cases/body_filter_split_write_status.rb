# An mruby body filter on a response that a handler wrote with Nginx.rputs
# and sent with a status set before or after the output, in more than one
# write.
# Config: test/conf/conf.d/90-body-filter-split-write-status.conf (port 18142).
#
# Each request is an HTTP/1.0 request through tcp_client, which reads until
# nginx closes the connection. A response that stops after its first write
# ends when send_timeout (3 seconds) closes the connection, so the case
# fails within seconds instead of blocking the run.

t = SimpleTest.new "ngx_mruby test: a body filter on a response with a status sent in several writes"

# Sends GET path and returns the status of the connection, the status line,
# the response headers (names in lower case) and the body.
def split_write_status_request(path)
  status, raw = tcp_client(18142, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
  head, body = raw.split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  headers = {}
  lines[1..-1].to_a.each do |line|
    name, value = line.split(": ", 2)
    headers[name.downcase] = value
  end
  [status, lines[0].to_s, headers, body.to_s]
end

t.assert('body filter split write with a status', '201 after the output with sendfile_max_chunk') do
  status, line, headers, body = split_write_status_request('/created_after_max_chunk')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 201 Created', line
  t.assert_equal '4000', headers['content-length']
  t.assert_equal 4000, body.bytesize
  t.assert_equal 'A' * 4000, body
end

t.assert('body filter split write with a status', '201 after the output with limit_rate') do
  status, line, headers, body = split_write_status_request('/created_after_limit_rate')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 201 Created', line
  t.assert_equal '2500', headers['content-length']
  t.assert_equal 2500, body.bytesize
  t.assert_equal 'A' * 2500, body
end

t.assert('body filter split write with a status', '403 after the output with sendfile_max_chunk') do
  status, line, headers, body = split_write_status_request('/forbidden_after_max_chunk')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 403 Forbidden', line
  t.assert_equal '4000', headers['content-length']
  t.assert_equal 4000, body.bytesize
  t.assert_equal 'A' * 4000, body
end

t.assert('body filter split write with a status', '403 after the output with a header filter and sendfile_max_chunk') do
  status, line, headers, body = split_write_status_request('/forbidden_after_both_filters_max_chunk')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 403 Forbidden', line
  t.assert_equal '1', headers['x-header-filter-runs']
  t.assert_equal '4000', headers['content-length']
  t.assert_equal 4000, body.bytesize
  t.assert_equal 'A' * 4000, body
end

t.assert('body filter split write with a status', '403 before the output with sendfile_max_chunk') do
  status, line, headers, body = split_write_status_request('/forbidden_before_max_chunk')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 403 Forbidden', line
  t.assert_equal '4000', headers['content-length']
  t.assert_equal 4000, body.bytesize
  t.assert_equal 'A' * 4000, body
end

t.assert('body filter split write with a status', '403 after the output of a rewrite handler with sendfile_max_chunk') do
  status, line, headers, body = split_write_status_request('/rewrite_forbidden_after_max_chunk')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 403 Forbidden', line
  t.assert_equal '4000', headers['content-length']
  t.assert_equal 4000, body.bytesize
  t.assert_equal 'A' * 4000, body
end

t.report
