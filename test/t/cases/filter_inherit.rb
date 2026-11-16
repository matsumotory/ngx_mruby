# Output filters given at server level run in the locations below the server,
# a location inherits the filters of the location around it and its if
# blocks inherit those of the location, and a filter given in a location
# replaces the one of the same kind above it (section 2.4 of
# docs/proposals/core-alpha1.md).
# Config: test/conf/conf.d/99-filter-inherit.conf (port 18108).
#
# A request is sent with HTTP/1.0, so nginx closes the connection after the
# response and the body is what follows the header.

t = SimpleTest.new "ngx_mruby test: output filters inherited by locations"

# Sends GET path and returns [connection status, status line, header fields
# with their names in lower case, body].
def filter_inherit_get(path)
  status, raw = tcp_client(18108, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
  head, body = raw.split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  fields = {}
  (lines[1..-1] || []).each do |line|
    name, value = line.split(':', 2)
    fields[name.downcase] = value.to_s.strip
  end
  [status, lines[0].to_s, fields, body.to_s]
end

# path, body, whether the header filter of the server runs, and what the
# location runs instead of it
[
  ['/plain', 'plain', 'a location without a filter runs the header filter of its server'],
  ['/static', "static file\n", 'a location that serves a file runs the header filter of its server'],
  ['/outer', 'OUTER', 'a location with only a body filter runs the header filter of its server as well'],
  ['/outer/inner', 'INNER', 'a nested location runs the body filter of the location around it and the header filter of the server'],
  ['/if?in=1', 'IF', 'the if block of a location runs the body filter of the location and the header filter of the server'],
  ['/if', 'IF', 'the location around that if block, without the if block'],
].each do |path, body, desc|
  t.assert('filter inherit', "#{path}: #{desc}") do
    status, line, fields, got = filter_inherit_get(path)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal 'ran', fields['x-server-filter']
    t.assert_equal nil, fields['x-location-filter']
    t.assert_equal body, got
    t.assert_equal body.bytesize.to_s, fields['content-length']
  end
end

t.assert('filter inherit', '/own: the header filter of a location runs instead of the one of its server') do
  status, line, fields, got = filter_inherit_get('/own')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'ran', fields['x-location-filter']
  t.assert_equal nil, fields['x-server-filter']
  t.assert_equal 'own', got
end

t.assert('filter inherit', 'a request that matches no location runs the header filter of the server') do
  status, line, fields, _got = filter_inherit_get('/none')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 404 Not Found', line
  t.assert_equal 'ran', fields['x-server-filter']
end

t.report
