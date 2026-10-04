# How handlers that read the request body (mruby_enable_read_request_body on)
# end when the rest of the body arrives after the handler started, and when
# the client closes the connection before the body is complete.
# Config: test/conf/conf.d/64-request-body-later.conf (port 18144).

t = SimpleTest.new "ngx_mruby test: request body that arrives after the handler started"

# [Host header, path, kind of the handler that reads the body]
REQUEST_BODY_LATER_HANDLERS = [
  ['post-read.request-body-later.test', '/', 'post-read'],
  ['server-rewrite.request-body-later.test', '/', 'server rewrite'],
  ['localhost', '/rewrite', 'rewrite'],
  ['localhost', '/access', 'access'],
  ['localhost', '/content', 'content'],
]

# Sends the body in two halves; returns the status of the connection, the
# status line and the body of the response.
def request_body_later_parts(host, path)
  out = `ruby test/t/cases/_request_body_client.rb parts 18144 #{host} #{path}`
  status, hex = out.split(":", 2)
  head, body = [hex.to_s].pack("H*").split("\r\n\r\n", 2)
  [status, head.to_s.split("\r\n")[0].to_s, body.to_s]
end

# Opens three connections that send part of the body and close them; returns
# the output of the helper ("before=N after=M" or "unsupported").
def request_body_later_close(host, path)
  `ruby test/t/cases/_request_body_client.rb close 18144 #{host} #{path} 3`
end

REQUEST_BODY_LATER_HANDLERS.each do |host, path, kind|
  t.assert('request body later', "a #{kind} handler answers after the rest of the body arrived") do
    status, line, body = request_body_later_parts(host, path)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal 'body=0123456789abcdefghij', body
  end
end

# A socket of port 18144 in CLOSE_WAIT is a connection that the client has
# closed and nginx still keeps open. When the client closes before the body
# is complete, nginx must close the connection and free the request, so the
# number of such sockets must come back to what it was before the three
# connections. /proc/net/tcp exists on Linux only; elsewhere the helper
# prints "unsupported" and the check is skipped.
REQUEST_BODY_LATER_HANDLERS.each do |host, path, kind|
  t.assert('request body later', "a #{kind} handler lets nginx close the connection when the client closes before the body is complete") do
    out = request_body_later_close(host, path)
    unless out == 'unsupported'
      counts = {}
      out.split(' ').each do |pair|
        key, value = pair.split('=', 2)
        counts[key] = value
      end
      t.assert_equal counts['before'], counts['after']
    end
  end
end

t.report
