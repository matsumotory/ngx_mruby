# A header filter and a body filter that makes the body longer, in the same
# location, with a static file and with Nginx.rputs as the origin.
# Config: test/conf/conf.d/65-header-and-body-filter.conf (port 18150).

t = SimpleTest.new "ngx_mruby test: a header filter and a body filter that changes the length"

# Splits the bytes that nginx sent on one connection into count responses by
# their Content-Length. Returns [status line, header fields (names in lower
# case), body] for each response, and the bytes after the last one.
def header_and_body_filter_split(raw, count)
  responses = []
  rest = raw
  count.times do
    head, after = rest.split("\r\n\r\n", 2)
    lines = head.to_s.split("\r\n")
    fields = {}
    lines[1..-1].to_a.each do |l|
      name, value = l.split(':', 2)
      fields[name.downcase] = value.to_s.strip
    end
    length = fields['content-length'].to_i
    after = after.to_s
    responses << [lines[0].to_s, fields, after.byteslice(0, length).to_s]
    rest = after.byteslice(length, after.bytesize).to_s
  end
  [responses, rest]
end

HEADER_AND_BODY_FILTER_BODIES = {
  '/static' => "static file\n(processed by body_filter)",
  '/rputs' => 'rputs origin(processed by body_filter)',
}

# Two requests on one HTTP/1.1 connection, sent together; the second one
# closes the connection. A response whose header announced fewer bytes than
# its body has would leave the rest in front of the second response.
[['/static', '/rputs'], ['/rputs', '/static']].each do |first, second|
  t.assert('header and body filter', "#{first} then #{second} on one connection: each response has the length of its body") do
    payload = "GET #{first} HTTP/1.1\r\nHost: localhost\r\n\r\n" +
              "GET #{second} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    status, raw = tcp_client(18150, payload)
    t.assert_equal 'EOF', status
    responses, rest = header_and_body_filter_split(raw, 2)
    [first, second].each_with_index do |path, i|
      line, fields, body = responses[i]
      t.assert_equal 'HTTP/1.1 200 OK', line
      t.assert_equal 'ran', fields['x-header-filter']
      t.assert_equal HEADER_AND_BODY_FILTER_BODIES[path], body
      t.assert_equal HEADER_AND_BODY_FILTER_BODIES[path].bytesize.to_s, fields['content-length']
    end
    t.assert_equal '', rest
  end
end

t.report
