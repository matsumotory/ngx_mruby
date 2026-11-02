# HEAD must send no body and leave a kept connection usable by the next
# request. Reuses test/conf/conf.d/20-filter-connection.conf (port 18112),
# with the bounded raw socket helper _head_filter_client.rb.
# This covers the known-length body-filter finalizer, not the separate
# unknown-length bypass or header-filter-only paths.
t = SimpleTest.new "ngx_mruby test: HEAD with an output body filter"

def head_filter_parse(raw)
  header, body = raw.split("\r\n\r\n", 2)
  lines = header.to_s.split("\r\n")
  fields = {}
  (lines[1..-1] || []).each do |line|
    name, value = line.split(":", 2)
    fields[name.downcase] = value.strip unless value.nil?
  end
  [lines[0].to_s, fields, body.to_s]
end

[
  ['HEAD', '/backend', '12', ''],
  ['GET', '/filter/output_return', '7', 'hello|5'],
  ['HEAD', '/filter/output_return', '7', ''],
  ['HEAD', '/filter/output_rputs_origin', '17', ''],
  ['HEAD', '/filter/output_empty', '0', '']
].each do |method, path, length, expected_body|
  t.assert('HEAD/body-filter connection', "#{method} #{path}, then GET on the same connection") do
    status1, hex1, status2, hex2 = `ruby ./test/t/cases/_head_filter_client.rb #{method} #{path}`.strip.split(':', 4)
    line1, fields1, body1 = head_filter_parse([hex1.to_s].pack('H*'))
    line2, fields2, body2 = head_filter_parse([hex2.to_s].pack('H*'))
    t.assert_equal 'COMPLETE', status1
    t.assert_equal 'HTTP/1.1 200 OK', line1
    t.assert_equal length, fields1['content-length']
    t.assert_equal 'keep-alive', fields1['connection']
    t.assert_equal expected_body, body1
    t.assert_equal 'EOF', status2
    t.assert_equal 'HTTP/1.1 200 OK', line2
    t.assert_equal '12', fields2['content-length']
    t.assert_equal 'backend body', body2
  end
end

t.report
