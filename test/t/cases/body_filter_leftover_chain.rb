# An mruby body filter that runs while an earlier handler's Nginx.rputs
# output is still in the module context, on a response sent in more than one
# write.
# Config: test/conf/conf.d/90-body-filter-leftover-chain.conf (port 18145).
#
# The header filter of the first four locations counts its runs in
# X-Header-Filter-Runs; the last two locations have no header filter.
#
# Each request is an HTTP/1.0 request through tcp_client, which reads until
# nginx closes the connection. A response that stops after its first write
# ends when send_timeout (3 seconds) closes the connection, so the case
# fails within seconds instead of blocking the run.

t = SimpleTest.new "ngx_mruby test: a body filter after a leftover Nginx.rputs output"

# Sends GET path and returns the status of the connection, the status line,
# the response headers (names in lower case) and the body.
def leftover_chain_request(path)
  status, raw = tcp_client(18145, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
  head, body = raw.split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  headers = {}
  lines[1..-1].to_a.each do |line|
    name, value = line.split(": ", 2)
    headers[name.downcase] = value
  end
  [status, lines[0].to_s, headers, body.to_s]
end

[
  ['a static file with sendfile_max_chunk', '/static_max_chunk', '1'],
  ['a static file with limit_rate', '/static_limit_rate', '1'],
  ['proxy_pass with sendfile_max_chunk', '/proxy_max_chunk', '1'],
  ['proxy_pass without buffering, with sendfile_max_chunk', '/proxy_unbuffered_max_chunk', '1'],
  ['a static file with sendfile_max_chunk and no header filter', '/static_body_filter_only_max_chunk', nil],
  ['a static file with limit_rate and no header filter', '/static_body_filter_only_limit_rate', nil],
].each do |name, path, header_filter_runs|
  t.assert('body filter leftover chain', name) do
    status, line, headers, body = leftover_chain_request(path)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal header_filter_runs, headers['x-header-filter-runs']
    t.assert_equal '4000', headers['content-length']
    t.assert_equal 4000, body.bytesize
    t.assert_equal 'A' * 4000, body
  end
end

t.report
