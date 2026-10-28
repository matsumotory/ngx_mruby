# The example of the home page of the site (docs/proposals/site.md, 3.3
# item 8). The site copies test/conf/conf.d/70-home-example.conf,
# test/html/home_example.rb and the two files below into the page, so this
# case compares the response with what the page shows: the status line, each
# header that home_example.response lists, and the whole body.
# Config: test/conf/conf.d/70-home-example.conf (port 18160).

t = SimpleTest.new "ngx_mruby test: the example of the home page of the site"

# Reads a file of test/html as lines without their line ends.
def home_example_lines(name)
  File.open(html_path(name)) { |f| f.read }.split("\n", -1)
end

# Splits raw response bytes into the status line, the header fields (names in
# lower case) and the body, decoding a chunked body.
def home_example_parse(raw)
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

request = home_example_lines('home_example.request').reject { |l| l.empty? }
expected = home_example_lines('home_example.response')
blank = expected.index('')
expected_status = expected[0]
expected_fields = expected[1...blank]
expected_body = expected[(blank + 1)..-1].join("\n")

status, raw = tcp_client(18160, request.join("\r\n") + "\r\n\r\n")
got_status, got_fields, got_body = home_example_parse(raw)

t.assert('home page example', "#{request[0]}: the server closes the connection after the response") do
  t.assert_equal 'EOF', status
end

t.assert('home page example', "#{request[0]}: the status line of home_example.response") do
  t.assert_equal expected_status, got_status
end

expected_fields.each do |field|
  name, value = field.split(':', 2)
  t.assert('home page example', "#{request[0]}: the header #{name} of home_example.response") do
    t.assert_equal value.strip, got_fields[name.downcase]
  end
end

t.assert('home page example', "#{request[0]}: the whole body of home_example.response") do
  t.assert_equal expected_body, got_body
end

t.report
