# HEAD must send no body and leave a kept connection usable by the next
# request, also when the response passes an mruby filter on the two paths
# that test/t/cases/head_body_filter.rb does not cover:
# - a location with an mruby header filter and no body filter, which passes
#   the header on after the code of the header filter has run;
# - a location with an mruby body filter whose response has no
#   Content-Length (an autoindex listing), for which the body filter passes
#   the header and the body on without running its code.
# Server config: test/conf/conf.d/20-filter-connection.conf (port 18112).
# Raw socket helper: test/t/cases/_head_filter_client.rb (CRuby), which sends
# the request, then GET /backend on the same connection.
t = SimpleTest.new "ngx_mruby test: HEAD with an output header filter"

def head_header_filter_parse(raw)
  header, body = raw.split("\r\n\r\n", 2)
  lines = header.to_s.split("\r\n")
  fields = {}
  (lines[1..-1] || []).each do |line|
    name, value = line.split(":", 2)
    fields[name.downcase] = value.strip unless value.nil?
  end
  [lines[0].to_s, fields, body.to_s]
end

def head_header_filter_exchange(method, path)
  out = `ruby ./test/t/cases/_head_filter_client.rb #{method} #{path}`.strip
  status1, hex1, status2, hex2 = out.split(':', 4)
  [status1, head_header_filter_parse([hex1.to_s].pack('H*')),
   status2, head_header_filter_parse([hex2.to_s].pack('H*'))]
end

# The header filter alone: HEAD and a GET control, for a response of the
# return directive and one of nginx's static file handler.
[
  ['HEAD', '/filter/header_return', '6', ''],
  ['GET', '/filter/header_return', '6', 'origin'],
  ['HEAD', '/filter/header_static', '12', ''],
  ['GET', '/filter/header_static', '12', "static file\n"]
].each do |method, path, length, expected_body|
  t.assert('HEAD/header-filter connection', "#{method} #{path}, then GET on the same connection") do
    status1, first, status2, second = head_header_filter_exchange(method, path)
    line1, fields1, body1 = first
    line2, fields2, body2 = second
    t.assert_equal 'COMPLETE', status1
    t.assert_equal 'HTTP/1.1 200 OK', line1
    t.assert_equal length, fields1['content-length']
    t.assert_equal 'ran', fields1['x-header-filter']
    t.assert_equal 'keep-alive', fields1['connection']
    t.assert_equal expected_body, body1
    t.assert_equal 'EOF', status2
    t.assert_equal 'HTTP/1.1 200 OK', line2
    t.assert_equal '12', fields2['content-length']
    t.assert_equal 'backend body', body2
  end
end

# A body filter on a response without Content-Length: HEAD gets the header
# without a length and without a body, and the connection stays usable.
t.assert('HEAD/body-filter connection', 'HEAD of a response without Content-Length, then GET on the same connection') do
  status1, first, status2, second = head_header_filter_exchange('HEAD', '/filter/body_unknown_length/')
  line1, fields1, body1 = first
  line2, fields2, body2 = second
  t.assert_equal 'COMPLETE', status1
  t.assert_equal 'HTTP/1.1 200 OK', line1
  t.assert_nil fields1['content-length']
  t.assert_nil fields1['transfer-encoding']
  t.assert_equal 'keep-alive', fields1['connection']
  t.assert_equal '', body1
  t.assert_equal 'EOF', status2
  t.assert_equal 'HTTP/1.1 200 OK', line2
  t.assert_equal '12', fields2['content-length']
  t.assert_equal 'backend body', body2
end

# The same response sent at 50 bytes a second: the header of the HEAD
# response needs more than one write, and its rest goes out when nginx
# calls the filters again with no new data.
t.assert('HEAD/body-filter connection', 'HEAD of a response without Content-Length sent in more than one write, then GET on the same connection') do
  status1, first, status2, second = head_header_filter_exchange('HEAD', '/filter/body_unknown_length_slow/')
  line1, fields1, body1 = first
  line2, fields2, body2 = second
  t.assert_equal 'COMPLETE', status1
  t.assert_equal 'HTTP/1.1 200 OK', line1
  t.assert_nil fields1['content-length']
  t.assert_equal 'keep-alive', fields1['connection']
  t.assert_equal '', body1
  t.assert_equal 'EOF', status2
  t.assert_equal 'HTTP/1.1 200 OK', line2
  t.assert_equal '12', fields2['content-length']
  t.assert_equal 'backend body', body2
end

# The GET control of the same location: the listing goes out unchanged,
# without a length, and the connection closes after it (HTTP/1.0).
t.assert('HEAD/body-filter connection', 'GET of a response without Content-Length') do
  status, raw = tcp_client(18112, "GET /filter/body_unknown_length/ HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, fields, body = head_header_filter_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_nil fields['content-length']
  t.assert_true body.include?('matsumotory.png')
  t.assert_false body.include?('replaced')
end

t.report
