# The samples of the guides and use cases of the site (docs/proposals/site.md,
# 3.5 "Samples"). The site copies the configuration, the script, the request
# and the response file of each sample into its page, so this case sends each
# request file and compares the response with the response file: the status
# line, each header that the file lists, and the whole body.
# Config: test/conf/conf.d/72-guide-hello.conf (port 18161),
# 73-guide-routing.conf (18163, backends 18164 and 18165), 74-guide-access.conf
# (18162), 75-guide-rate-limit.conf (18166), 76-guide-body-filter.conf (18167),
# stream/42-guide-tcp.conf (12364) with 77-guide-tcp-backend.conf (18168).

t = SimpleTest.new "ngx_mruby test: the samples of the guides of the site"

# Reads a file of test/html as lines without their line ends.
def guide_lines(name)
  File.open(html_path(name)) { |f| f.read }.split("\n", -1)
end

# Splits raw response bytes into the status line, the header fields (names in
# lower case) and the body, decoding a chunked body.
def guide_parse(raw)
  head, body = raw.split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  fields = {}
  lines[1..-1].to_a.each do |l|
    name, value = l.split(':', 2)
    fields[name.downcase] = value.to_s.strip
  end
  body = body.to_s
  if fields['transfer-encoding'] == 'chunked'
    decoded = ''
    rest = body
    loop do
      size_line, rest = rest.split("\r\n", 2)
      size = size_line.to_s.to_i(16)
      break if size == 0
      decoded += rest.to_s.byteslice(0, size).to_s
      rest = rest.to_s.byteslice(size + 2, rest.to_s.bytesize).to_s
    end
    body = decoded
  end
  [lines[0].to_s, fields, body]
end

# Sends the request of the file request_name to port and returns the status
# of the connection, the request line and the parsed response.
def guide_send(port, request_name)
  request = guide_lines(request_name).reject { |l| l.empty? }
  status, raw = tcp_client(port, request.join("\r\n") + "\r\n\r\n")
  [status, request[0]] + guide_parse(raw)
end

# Sends the request of request_name to port and compares the response with
# the file response_name.
def guide_compare(t, sample, port, request_name, response_name)
  expected = guide_lines(response_name)
  blank = expected.index('')
  expected_fields = expected[1...blank]
  expected_body = expected[(blank + 1)..-1].join("\n")
  status, line, got_status, got_fields, got_body = guide_send(port, request_name)

  t.assert(sample, "#{line} to #{port}: the server closes the connection after the response") do
    t.assert_equal 'EOF', status
  end
  t.assert(sample, "#{line} to #{port}: the status line of #{response_name}") do
    t.assert_equal expected[0], got_status
  end
  expected_fields.each do |field|
    name, value = field.split(':', 2)
    t.assert(sample, "#{line} to #{port}: the header #{name} of #{response_name}") do
      t.assert_equal value.strip, got_fields[name.downcase]
    end
  end
  t.assert(sample, "#{line} to #{port}: the whole body of #{response_name}") do
    t.assert_equal expected_body, got_body
  end
end

guide_compare(t, 'use case: hello world', 18161, 'guide_hello.request', 'guide_hello.response')

guide_compare(t, 'guide: routing', 18163, 'guide_routing.request', 'guide_routing.response')
t.assert('guide: routing', 'a request without X-Tenant goes to backend a') do
  status, raw = tcp_client(18163, "GET /orders HTTP/1.1\r\nHost: 127.0.0.1:18163\r\nConnection: close\r\n\r\n")
  got_status, _, got_body = guide_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', got_status
  t.assert_equal "backend a on port 18164\n", got_body
end

guide_compare(t, 'guide: access control', 18162, 'guide_access.request', 'guide_access.response')
t.assert('guide: access control', 'a location whose list does not hold the client answers 200') do
  status, raw = tcp_client(18162, "GET /open/report HTTP/1.1\r\nHost: 127.0.0.1:18162\r\nConnection: close\r\n\r\n")
  got_status, _, got_body = guide_parse(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', got_status
  t.assert_equal "welcome\n", got_body
end

# The first request of the key passes; the second, within the minute of
# rate=1r/m, gets the 429 of guide_rate_limit.response.
t.assert('guide: rate limit', 'the first request of the key answers 200') do
  _, _, got_status, _, got_body = guide_send(18166, 'guide_rate_limit.request')
  t.assert_equal 'HTTP/1.1 200 OK', got_status
  t.assert_equal "accepted\n", got_body
end
guide_compare(t, 'guide: rate limit', 18166, 'guide_rate_limit.request', 'guide_rate_limit.response')

guide_compare(t, 'guide: body filter', 18167, 'guide_body_filter.request', 'guide_body_filter.response')

guide_compare(t, 'guide: tcp', 12364, 'guide_tcp.request', 'guide_tcp.response')

t.report
