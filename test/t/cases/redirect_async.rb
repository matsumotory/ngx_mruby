# Nginx.redirect with a local URI takes effect when the calling handler ends:
# one handler answers each request, the target's handlers wait like any
# handler, the output and the status that the calling handler sets after
# the call are not sent (error.log has a line at the warn level), and the
# access log has the status of the answer.
# Config: test/conf/conf.d/85-redirect-async.conf (port 18186).

t = SimpleTest.new "ngx_mruby test: Nginx.redirect takes effect when the handler ends"

# Splits the bytes of pipelined responses into [status line, body] pairs,
# using Content-Length.
def redirect_async_responses(raw)
  responses = []
  rest = raw
  while rest.start_with?('HTTP/1.1 ')
    head, rest = rest.split("\r\n\r\n", 2)
    rest = rest.to_s
    lines = head.split("\r\n")
    length = nil
    lines.each do |l|
      name, value = l.split(':', 2)
      length = value.strip.to_i if name.downcase == 'content-length'
    end
    if length.nil?
      responses << ['no Content-Length: ' + lines[0].to_s, rest]
      break
    end
    responses << [lines[0], rest[0, length]]
    rest = rest[length..-1].to_s
  end
  responses
end

def redirect_async_get(path)
  status, raw = tcp_client(18186, "GET #{path} HTTP/1.1\r\nHost: localhost\r\n\r\n" \
                                  "GET /target_plain HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
  [status, redirect_async_responses(raw)]
end

# The lines of a log file that contain text, from its last 1,000,000 bytes.
def redirect_async_log_lines(name, text)
  path = File.join(ENV['NGINX_INSTALL_DIR'], 'logs', name)
  return [] unless File.exist?(path)

  log = File.open(path) do |f|
    f.seek([File.size(path) - 1_000_000, 0].max)
    f.read
  end
  log.split("\n").select { |l| l.include?(text) }
end

[
  ['/redirect_then_output', 'a rewrite handler that redirects and then writes output: the target, which sleeps, answers alone',
   'from the target after its sleep'],
  ['/redirect_to_sleeping_content', 'a redirect to a content handler that sleeps: the content handler answers after its sleep',
   'slept'],
  ['/sleep_then_redirect', 'a content handler that sleeps and then redirects: the target answers', 'plain'],
  ['/redirect_then_status', 'a rewrite handler that redirects and then sets 503: the target answers, without the 503', 'plain'],
].each do |path, what, body|
  t.assert('redirect', "#{what}, and the next request on the connection is answered") do
    status, responses = redirect_async_get(path)
    t.assert_equal 'EOF', status
    t.assert_equal 2, responses.size
    t.assert_equal ['HTTP/1.1 200 OK', body], responses[0]
    t.assert_equal ['HTTP/1.1 200 OK', 'plain'], responses[1]
    # the access log has one line for the request, with the status of the
    # answer
    lines = redirect_async_log_lines('redirect_async_access.log', "\"GET #{path} HTTP/1.1\"")
    t.assert_include lines[-1].to_s, '" 200 '
  end
end

t.assert('redirect', 'the output and the status set after Nginx.redirect are not sent, and error.log says so for each request') do
  lines = redirect_async_log_lines('error.log', 'set after Nginx.redirect are not sent')
  %w[/redirect_then_output /redirect_then_status].each do |path|
    t.assert_true lines.any? { |l| l.include?("request: \"GET #{path} HTTP/1.1\"") }, "no warn line for #{path}"
  end
  t.assert_false lines.any? { |l| l.include?('request: "GET /redirect_to_sleeping_content HTTP/1.1"') }
end

t.report
