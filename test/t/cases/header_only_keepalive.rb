# A response that ends at its header without HEAD (304 to a GET with
# If-Modified-Since, 204) must send no body and leave a kept connection
# usable by the next request, also when it passes an mruby header filter
# alone or an mruby body filter. test/t/cases/head_body_filter.rb and
# test/t/cases/head_header_filter.rb cover HEAD.
# Server config: test/conf/conf.d/20-filter-connection.conf (port 18112).
# Raw socket helper: test/t/cases/_head_filter_client.rb (CRuby), which sends
# the request, then GET /backend on the same connection.
t = SimpleTest.new "ngx_mruby test: 204 and 304 with an output filter"

def header_only_parse(raw)
  header, body = raw.split("\r\n\r\n", 2)
  lines = header.to_s.split("\r\n")
  fields = {}
  (lines[1..-1] || []).each do |line|
    name, value = line.split(":", 2)
    fields[name.downcase] = value.strip unless value.nil?
  end
  [lines[0].to_s, fields, body.to_s]
end

def header_only_exchange(method, path, headers = '')
  hex = headers.unpack('H*')[0]
  out = `ruby #{suite_path('test/t/cases/_head_filter_client.rb')} #{method} #{path} #{hex}`.strip
  status1, hex1, status2, hex2 = out.split(':', 4)
  [status1, header_only_parse([hex1.to_s].pack('H*')),
   status2, header_only_parse([hex2.to_s].pack('H*'))]
end

# A date after the modification time of the file: with if_modified_since
# before, nginx answers 304.
IMS = "If-Modified-Since: Thu, 31 Dec 2037 23:59:59 GMT\r\n"

# /filter/body_static_304_small_buffer reads the file in two parts, so the
# body filter gets a buffer that the copy filter needs back for the rest of
# the file. HEAD with If-Modified-Since takes the same path as the 304.
# [method, path, request headers, status line, Content-Length,
#  X-Header-Filter, body]
[
  ['GET', '/filter/header_static_304', IMS, 'HTTP/1.1 304 Not Modified', nil, 'ran', ''],
  ['GET', '/filter/header_static_304', '', 'HTTP/1.1 200 OK', '14', 'ran', "sendfile body\n"],
  ['GET', '/filter/header_204', '', 'HTTP/1.1 204 No Content', nil, 'ran', ''],
  ['GET', '/filter/body_static_304', IMS, 'HTTP/1.1 304 Not Modified', nil, nil, ''],
  ['GET', '/filter/body_static_304', '', 'HTTP/1.1 200 OK', '8', nil, 'replaced'],
  ['GET', '/filter/body_204', '', 'HTTP/1.1 204 No Content', nil, nil, ''],
  ['GET', '/filter/body_static_304_small_buffer', IMS, 'HTTP/1.1 304 Not Modified', nil, nil, ''],
  ['HEAD', '/filter/body_static_304_small_buffer', IMS, 'HTTP/1.1 304 Not Modified', nil, nil, ''],
  ['GET', '/filter/body_static_304_small_buffer', '', 'HTTP/1.1 200 OK', '8', nil, 'replaced']
].each do |method, path, headers, status_line, length, filter_field, expected_body|
  name = headers.empty? ? "#{method} #{path}" : "#{method} #{path} with If-Modified-Since"
  t.assert('header-only connection', "#{name}, then GET on the same connection") do
    status1, first, status2, second = header_only_exchange(method, path, headers)
    line1, fields1, body1 = first
    line2, fields2, body2 = second
    t.assert_equal 'COMPLETE', status1
    t.assert_equal status_line, line1
    t.assert_equal length, fields1['content-length']
    t.assert_equal filter_field, fields1['x-header-filter']
    t.assert_equal 'keep-alive', fields1['connection']
    t.assert_equal expected_body, body1
    t.assert_equal 'EOF', status2
    t.assert_equal 'HTTP/1.1 200 OK', line2
    t.assert_equal '12', fields2['content-length']
    t.assert_equal 'backend body', body2
  end
end

t.report
