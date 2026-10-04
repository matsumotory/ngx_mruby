# How handlers that read the request body (mruby_enable_read_request_body on)
# end when the rest of the body arrives after the handler started, and when
# the client closes the connection before the body is complete.
# Config: test/conf/conf.d/64-request-body-later.conf (ports 18144, 18147,
# 18148 and 18149).

t = SimpleTest.new "ngx_mruby test: request body that arrives after the handler started"

# [Host header, path, kind of the handler that reads the body]
REQUEST_BODY_LATER_HANDLERS = [
  ['post-read.request-body-later.test', '/', 'post-read'],
  ['server-rewrite.request-body-later.test', '/', 'server rewrite'],
  ['localhost', '/rewrite', 'rewrite'],
  ['localhost', '/access', 'access'],
  ['localhost', '/content', 'content'],
]

# Sends the body in two halves (mode "parts") or with the headers ("whole");
# returns the status of the connection, the status line and the body of the
# response.
def request_body_later_parts(host, path, port = 18144, mode = 'parts')
  out = `ruby test/t/cases/_request_body_client.rb #{mode} #{port} #{host} #{path}`
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

# Port 18147: after a rewrite or an access handler has read a body that
# arrived late, the auth_request module waits for its subrequest, and nginx
# resumes the request through its write event handler when the subrequest
# ends. The request must then go on to the content handler. Afterwards no
# socket of port 18147 may stay in CLOSE_WAIT: a request that never resumed
# keeps its connection after the client gives up and closes it.
[['/rewrite', 'a rewrite handler'], ['/access', 'an access handler']].each do |path, handler|
  t.assert('request body later', "the request goes on to auth_request after #{handler} read the rest of the body") do
    status, line, body = request_body_later_parts('localhost', path, 18147)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal 'body=0123456789abcdefghij', body
  end
end

t.assert('request body later', 'no connection of the auth_request server stays open after its client closed it') do
  out = `ruby test/t/cases/_request_body_client.rb close_wait 18147`
  t.assert_equal 'close_wait=0', out unless out == 'unsupported'
end

# Port 18148: an mruby_set handler reads the body. It runs inside the rewrite
# phase and cannot wait, so it sees the body only when the whole body arrived
# with the request headers; otherwise it runs without the body, the variable
# is empty, and ngx_mruby logs that at the info level. The content handler
# (/content) and proxy_pass (/proxy, /proxy_return) read the whole body
# afterwards in both cases; the upstream of /proxy_return answers "plain"
# without reading it. error.log must not get an "[alert]" line for these
# requests (a content handler that ran twice logged "header already sent"),
# and the content handler's code must run once per request.
def request_body_set_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

# Lines that nginx appended to error.log after offset.
def request_body_set_log_lines(offset)
  File.open(request_body_set_log_path) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
end

REQUEST_BODY_SET_NOT_COMPLETE = 'the request body is not complete and an mruby_set handler cannot wait for it'
REQUEST_BODY_SET_CONTENT_RAN = 'request-body-set-content-code-ran'

[
  ['/content', 'whole', 'the content handler', 'var=[0123456789abcdefghij] body=[0123456789abcdefghij]', 0, 1],
  ['/content', 'parts', 'the content handler', 'var=[] body=[0123456789abcdefghij]', 1, 1],
  ['/proxy', 'whole', 'proxy_pass', 'var=[0123456789abcdefghij] body=[0123456789abcdefghij]', 0, 0],
  ['/proxy', 'parts', 'proxy_pass', 'var=[] body=[0123456789abcdefghij]', 1, 0],
  ['/proxy_return', 'whole', 'proxy_pass to a location that does not read it', 'plain', 0, 0],
  ['/proxy_return', 'parts', 'proxy_pass to a location that does not read it', 'plain', 1, 0],
].each do |path, mode, reader, expected, not_complete, content_runs|
  what = mode == 'whole' ? 'sees a body that arrived with the headers' : 'runs without a body that is not complete'
  t.assert('request body later', "an mruby_set handler #{what}, and #{reader} gets the whole body") do
    offset = File.size(request_body_set_log_path)
    status, line, body = request_body_later_parts('localhost', path, 18148, mode)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal expected, body
    lines = request_body_set_log_lines(offset)
    t.assert_equal [], lines.select { |l| l.include?('[alert]') }
    t.assert_equal not_complete, lines.select { |l| l.include?(REQUEST_BODY_SET_NOT_COMPLETE) }.size
    t.assert_equal content_runs, lines.select { |l| l.include?(REQUEST_BODY_SET_CONTENT_RAN) }.size
  end
end

t.assert('request body later', 'no connection of the mruby_set server stays open after its client closed it') do
  out = `ruby test/t/cases/_request_body_client.rb close_wait 18148`
  t.assert_equal 'close_wait=0', out unless out == 'unsupported'
end

t.report
