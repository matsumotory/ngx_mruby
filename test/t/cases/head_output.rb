# A HEAD request to a content handler that writes output gets the header
# without the body; a GET gets the body. Config:
# test/conf/conf.d/69-head-output.conf (port 18137). tcp_client is in
# test/t/cases/_prelude.rb (as test/t/cases/content_empty_body.rb uses it).

t = SimpleTest.new "ngx_mruby test: HEAD of a content handler that writes output"

# Splits a raw response into the status line, the header fields (a Hash keyed
# by the lower-case field name) and the rest of the bytes.
def head_output_parse(raw)
  head, body = raw.split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  fields = {}
  (lines[1..-1] || []).each do |line|
    name, value = line.split(":", 2)
    next if value.nil?

    fields[name.downcase] = value.strip
  end
  [lines[0].to_s, fields, body.to_s]
end

t.assert('ngx_mruby - HEAD of an output handler', 'GET gets the body') do
  status, raw = tcp_client(18137, "GET /head_output HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, fields, body = head_output_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal '2', fields['content-length']
  t.assert_equal 'ok', body
end

t.assert('ngx_mruby - HEAD of an output handler', 'HEAD gets the header without a body') do
  status, raw = tcp_client(18137, "HEAD /head_output HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, fields, body = head_output_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal '2', fields['content-length']
  t.assert_equal '', body
end

t.report
