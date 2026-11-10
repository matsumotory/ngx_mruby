# An mruby body filter that runs while an earlier handler's Nginx.rputs
# output is still in the module context, on a response sent in more than one
# write.
# Config: test/conf/conf.d/90-body-filter-leftover-chain.conf (port 18145).
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
  ['a static file with sendfile_max_chunk', '/static_max_chunk'],
  ['a static file with limit_rate', '/static_limit_rate'],
  ['proxy_pass with sendfile_max_chunk', '/proxy_max_chunk'],
  ['proxy_pass without buffering, with sendfile_max_chunk', '/proxy_unbuffered_max_chunk'],
].each do |name, path|
  t.assert('body filter leftover chain', name) do
    status, line, headers, body = leftover_chain_request(path)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal '1', headers['x-header-filter-runs']
    t.assert_equal '4000', headers['content-length']
    t.assert_equal 4000, body.bytesize
    t.assert_equal 'A' * 4000, body
  end
end

t.report
