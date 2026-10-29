# How handlers that read the request body (mruby_enable_read_request_body on)
# end when the rest of the body arrives after the handler started, and when
# the client closes the connection before the body is complete.
# Config: test/conf/conf.d/64-request-body-later.conf (ports 18144, 18147,
# 18148, 18149 and 18152).

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
# response, and then its header fields (names in lower case).
def request_body_later_parts(host, path, port = 18144, mode = 'parts')
  out = `ruby #{suite_path('test/t/cases/_request_body_client.rb')} #{mode} #{port} #{host} #{path}`
  status, hex = out.split(":", 2)
  head, body = [hex.to_s].pack("H*").split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  fields = {}
  lines[1..-1].to_a.each do |l|
    name, value = l.split(':', 2)
    fields[name.downcase] = value.to_s.strip
  end
  [status, lines[0].to_s, body.to_s, fields]
end

# Opens three connections that send part of the body and close them; returns
# the output of the helper ("before=N after=M" or "unsupported").
def request_body_later_close(host, path)
  `ruby #{suite_path('test/t/cases/_request_body_client.rb')} close 18144 #{host} #{path} 3`
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

# The paths below are those that docs/directives/README.md describes for
# mruby_enable_read_request_body, checked for a rewrite and a content
# handler, whose phase checkers are the two that need NGX_DONE to wait
# (post-read, server rewrite and access handlers go through the same
# callback).

# HTTP/1.1: after the response to the late body, the connection stays open
# for a second request.
[['/rewrite', 'a rewrite handler'], ['/content', 'a content handler']].each do |path, handler|
  t.assert('request body later', "the connection stays open for the next request after #{handler} answered a late body") do
    out = `ruby #{suite_path('test/t/cases/_request_body_client.rb')} keepalive 18144 localhost #{path}`
    status1, hex1, status2, hex2 = out.split(':', 4)
    head1, body1 = [hex1.to_s].pack('H*').split("\r\n\r\n", 2)
    head2, body2 = [hex2.to_s].pack('H*').split("\r\n\r\n", 2)
    t.assert_equal 'COMPLETE', status1
    t.assert_equal 'HTTP/1.1 200 OK', head1.to_s.split("\r\n")[0].to_s
    t.assert_equal 'body=0123456789abcdefghij', body1.to_s
    t.assert_equal 'EOF', status2
    t.assert_equal 'HTTP/1.1 200 OK', head2.to_s.split("\r\n")[0].to_s
    t.assert_equal 'plain', body2.to_s
  end
end

# client_body_timeout (2s in these locations) ends a request whose body
# stops arriving: nginx closes the connection without a response.
[['/rewrite_timeout', 'a rewrite handler'], ['/content_timeout', 'a content handler']].each do |path, handler|
  t.assert('request body later', "client_body_timeout ends the request when #{handler} waits for a body that stops arriving") do
    out = `ruby #{suite_path('test/t/cases/_request_body_client.rb')} timeout 18144 localhost #{path}`
    status, seconds, hex = out.split(':', 3)
    t.assert_equal 'EOF', status
    t.assert_equal '', [hex.to_s].pack('H*')
    t.assert_true seconds.to_f >= 1.5, "closed after #{seconds} s, before client_body_timeout"
    t.assert_true seconds.to_f < 8.0, "closed after #{seconds} s"
  end
end

# A handler that raises after it got the late body answers 500.
[['/rewrite_raise', 'a rewrite handler'], ['/content_raise', 'a content handler']].each do |path, handler|
  t.assert('request body later', "#{handler} that raises after the late body answers 500") do
    status, line, body = request_body_later_parts('localhost', path)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
    t.assert_include body, '<title>500 Internal Server Error</title>'
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
  out = `ruby #{suite_path('test/t/cases/_request_body_client.rb')} close_wait 18147`
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
  out = `ruby #{suite_path('test/t/cases/_request_body_client.rb')} close_wait 18148`
  t.assert_equal 'close_wait=0', out unless out == 'unsupported'
end

# Port 18152: a rewrite handler waits for the rest of the body, and the read
# ends without it. The log handler, header filter or body filter of the
# location then runs without the rest of the body, as these kinds do for a
# body that is not complete, and ngx_mruby logs that at the info level; the
# code of the rewrite handler does not run. Nginx::Request#body returns the
# part of the body that nginx had read before it ended the read: the log
# handler and the body filter log it, and the header filter writes it into
# the header X-Request-Body, all with inspect. After client_body_timeout
# nginx closes the connection without a response; for a malformed chunked
# body the client gets nginx's 400 page once, and the connection is closed.
# No "[alert]" line may follow for these requests, and afterwards no socket
# of port 18152 may stay in CLOSE_WAIT.
REQUEST_BODY_PENDING_RAN = 'request-body-pending-code-ran'
REQUEST_BODY_PENDING_LOGGED = 'request-body-pending-logged'
REQUEST_BODY_PENDING_FILTERED = 'request-body-pending-filtered'

def request_body_pending_not_complete(kind)
  "the request body is not complete and #{kind} cannot wait for it"
end

# What a handler of port 18152 logged with inspect as the body after marker
# (the log handler REQUEST_BODY_PENDING_LOGGED, the body filter
# REQUEST_BODY_PENDING_FILTERED), for each of its notice lines in lines.
# nginx adds the client and request data after the message, after " while
# logging request" in the log phase and after ", client: " in a filter.
def request_body_pending_logged(lines, marker)
  lines.map { |l| l.split("#{marker} ", 2)[1] }.compact.map { |v| v.split(' while ', 2)[0].split(', client: ', 2)[0] }
end

# How many times text occurs in str.
def request_body_count(str, text)
  count = 0
  pos = 0
  while (i = str.index(text, pos))
    count += 1
    pos = i + text.size
  end
  count
end

t.assert('request body later', 'a log handler runs without the body that a rewrite handler waits for when client_body_timeout ends the request') do
  offset = File.size(request_body_set_log_path)
  out = `ruby #{suite_path('test/t/cases/_request_body_client.rb')} timeout 18152 localhost /log_handler`
  status, seconds, hex = out.split(':', 3)
  t.assert_equal 'EOF', status
  t.assert_equal '', [hex.to_s].pack('H*')
  t.assert_true seconds.to_f >= 1.5, "closed after #{seconds} s, before client_body_timeout"
  t.assert_true seconds.to_f < 8.0, "closed after #{seconds} s"
  lines = request_body_set_log_lines(offset)
  t.assert_equal 0, lines.select { |l| l.include?(REQUEST_BODY_PENDING_RAN) }.size
  t.assert_equal 1, lines.select { |l| l.include?(request_body_pending_not_complete('a log handler')) }.size
  t.assert_equal [], lines.select { |l| l.include?('[alert]') }
  # The 10 bytes that the client sent before client_body_timeout expired.
  t.assert_equal ['"0123456789"'], request_body_pending_logged(lines, REQUEST_BODY_PENDING_LOGGED)
end

[['/header_filter', 'a header filter'], ['/body_filter', 'a body filter']].each do |path, kind|
  t.assert('request body later', "#{kind} runs without the body that a rewrite handler waits for when nginx rejects a malformed chunked body") do
    offset = File.size(request_body_set_log_path)
    status, line, body, fields = request_body_later_parts('localhost', path, 18152, 'bad_chunk')
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 400 Bad Request', line
    t.assert_equal 1, request_body_count(body, '<title>400 Bad Request</title>')
    t.assert_not_include body, 'body='
    # The data of the valid first chunk, which the client sent before the
    # malformed line.
    t.assert_equal '"abcde"', fields['x-request-body'] if path == '/header_filter'
    lines = request_body_set_log_lines(offset)
    # The body filter of /body_filter logs the same data of the first chunk.
    # (The conditional assertions stay off the last line of the block: a
    # block whose value is nil fails in SimpleTest.)
    t.assert_equal ['"abcde"'], request_body_pending_logged(lines, REQUEST_BODY_PENDING_FILTERED) if path == '/body_filter'
    t.assert_equal 0, lines.select { |l| l.include?(REQUEST_BODY_PENDING_RAN) }.size
    t.assert_equal 1, lines.select { |l| l.include?(request_body_pending_not_complete(kind)) }.size
    t.assert_equal [], lines.select { |l| l.include?('[alert]') }
  end
end

t.assert('request body later', 'no connection of the server whose read ended without the body stays open after its client closed it') do
  out = `ruby #{suite_path('test/t/cases/_request_body_client.rb')} close_wait 18152`
  t.assert_equal 'close_wait=0', out unless out == 'unsupported'
end

t.report
