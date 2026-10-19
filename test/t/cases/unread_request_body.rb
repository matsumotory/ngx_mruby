# Handlers that answer a POST without reading its body, and one that reads it.
# Config: test/conf/conf.d/66-unread-request-body.conf (port 18151).

t = SimpleTest.new "ngx_mruby test: a request body that the handler did not read"

# Splits the bytes that nginx sent on one connection into responses by their
# Content-Length, until no bytes are left. Returns [status line, body] for
# each response.
def unread_request_body_split(raw)
  responses = []
  rest = raw
  until rest.empty?
    head, after = rest.split("\r\n\r\n", 2)
    lines = head.to_s.split("\r\n")
    length = 0
    lines[1..-1].to_a.each do |l|
      name, value = l.split(':', 2)
      length = value.to_s.strip.to_i if name.downcase == 'content-length'
    end
    after = after.to_s
    responses << [lines[0].to_s, after.byteslice(0, length).to_s]
    rest = after.byteslice(length, after.bytesize).to_s
  end
  responses
end

# The body of the POST is a complete request for /leaf. After the POST the
# client sends GET /next on the same connection, which closes it.
UNREAD_REQUEST_BODY_INNER = "GET /leaf HTTP/1.1\r\nHost: localhost\r\n\r\n"

def unread_request_body_exchange(path)
  payload = "POST #{path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: #{UNREAD_REQUEST_BODY_INNER.bytesize}\r\n\r\n" +
            UNREAD_REQUEST_BODY_INNER +
            "GET /next HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
  status, raw = tcp_client(18151, payload)
  [status, unread_request_body_split(raw)]
end

[
  ['/answer', 'a content handler', 'answer'],
  ['/rewrite_answer', 'a rewrite handler', 'rewrite answer'],
  ['/rewrite_sleep_answer', 'a rewrite handler resumed after Nginx::Async.sleep', 'slept answer'],
].each do |path, handler, answer|
  t.assert('unread request body', "#{handler} that does not read the body answers once, and the next request gets its own answer") do
    status, responses = unread_request_body_exchange(path)
    t.assert_equal 'EOF', status
    t.assert_equal [['HTTP/1.1 200 OK', answer], ['HTTP/1.1 200 OK', 'next']], responses
  end
end

t.assert('unread request body', 'a content handler that reads the body still gets all of it') do
  status, responses = unread_request_body_exchange('/read_body')
  t.assert_equal 'EOF', status
  t.assert_equal [['HTTP/1.1 200 OK', "body=[#{UNREAD_REQUEST_BODY_INNER}]"], ['HTTP/1.1 200 OK', 'next']], responses
end

t.report
