# An mruby content handler or body filter in a location that an SSI page
# includes, so that the handler runs in a subrequest.
# Config: test/conf/conf.d/91-ssi-body-filter.conf (port 18146) and
# test/html/ssi_body_filter_part.txt ("middle").
#
# HTTP/1.0 requests read the body until nginx closes the connection; HTTP/1.1
# requests with "Connection: close" get the body in chunks, which the case
# decodes. A response that stops early ends when send_timeout (3 seconds)
# closes the connection, so the case fails within seconds instead of
# blocking the run. A response that splits the chunked body with a mid-
# stream terminator decodes to a body short of the expected text, and the
# dechunk returns ended=true before the expected tail is in the data.

t = SimpleTest.new "ngx_mruby test: a content handler or body filter in an SSI subrequest"

# Sends GET path and returns the status of the connection, the status line,
# the response headers (names in lower case) and the body as received.
def ssi_body_filter_request(path, version)
  extra = version == 'HTTP/1.1' ? "Connection: close\r\n" : ''
  status, raw = tcp_client(18146, "GET #{path} #{version}\r\nHost: localhost\r\n#{extra}\r\n")
  head, body = raw.split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  headers = {}
  lines[1..-1].to_a.each do |line|
    name, value = line.split(": ", 2)
    headers[name.downcase] = value
  end
  [status, lines[0].to_s, headers, body.to_s]
end

# Decodes a chunked body. Returns the data and whether the body ended with
# the last chunk and nothing after it.
def ssi_body_filter_dechunk(body)
  data = ''
  rest = body
  loop do
    size_line, rest = rest.split("\r\n", 2)
    return [data, false] if rest.nil?
    size = size_line.to_i(16)
    return [data, rest == "\r\n"] if size == 0
    data += rest[0, size]
    rest = rest[(size + 2)..-1].to_s
  end
end

[
  ['a static file', '/ssi/static', 'before MIDDLE after'],
  ['a static file, with a header filter', '/ssi/static_header', 'before MIDDLE after'],
  ['a static file, with a longer body', '/ssi/static_longer', 'before [MIDDLE] after'],
  ['an Nginx.rputs content handler', '/ssi/content', 'before MIDDLE after'],
  ['an Nginx.rputs content handler, with a header filter', '/ssi/content_header', 'before MIDDLE after'],
  ['an Nginx.rputs content handler with no body filter', '/ssi/content_raw', 'before middle after'],
  ['a static file, included twice', '/ssi/static_twice', 'before MIDDLE and MIDDLE after'],
].each do |name, path, expected|
  t.assert('ssi body filter', "#{name}, HTTP/1.0") do
    status, line, headers, body = ssi_body_filter_request(path, 'HTTP/1.0')
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal nil, headers['content-length']
    t.assert_equal expected, body
  end

  t.assert('ssi body filter', "#{name}, HTTP/1.1 in chunks") do
    status, line, headers, body = ssi_body_filter_request(path, 'HTTP/1.1')
    data, ended = ssi_body_filter_dechunk(body)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal 'chunked', headers['transfer-encoding']
    t.assert_equal expected, data
    t.assert_true ended
  end
end

t.report
