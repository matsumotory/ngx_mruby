# The result of a handler is its own: on a server whose server rewrite
# handler stores Nginx::DECLINED for every request, a later handler ends by
# the result it sets, with or without a wait.
# Config: test/conf/conf.d/82-async-result-isolation.conf (port 18179) and
# test/html/async_resume_result.rb.
#
# The cases list only the ends where the later handler's own result already
# decides. The proposal docs/proposals/core-stabilization.md (section 8) adds
# the others with the change that keeps the result of a handler for that
# handler.

t = SimpleTest.new "ngx_mruby test: the result of a handler is its own"

# Splits the bytes of pipelined responses into [status line, body] pairs,
# using Content-Length.
def async_isolation_responses(raw)
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
    length = rest.size if length.nil?
    responses << [lines[0], rest[0, length]]
    rest = rest[length..-1].to_s
  end
  responses
end

ASYNC_ISOLATION_WAITS = {
  'nowait' => 'without a wait',
  'sleep' => 'after Nginx::Async.sleep',
  'sub_request' => 'after Nginx::Async::HTTP.sub_request',
}

# [path, what the later handler does, status line, body (or the title of
# nginx's error page)]
[
  ['/access_all/WAIT/none', 'an access handler under satisfy all that sets no result goes on', %w[nowait sleep],
   'HTTP/1.1 200 OK', "passed\n"],
  ['/access_all/WAIT/forbidden', 'an access handler under satisfy all that returns 403 answers 403', %w[nowait sleep],
   'HTTP/1.1 403 Forbidden', '<title>403 Forbidden</title>'],
  ['/access_any/WAIT/ok', 'an access handler under satisfy any that returns Nginx::OK allows the request', %w[nowait],
   'HTTP/1.1 200 OK', "passed\n"],
  ['/rewrite/WAIT/forbidden', 'a rewrite handler that returns 403 answers 403', %w[nowait sleep sub_request],
   'HTTP/1.1 403 Forbidden', '<title>403 Forbidden</title>'],
  ['/rewrite/WAIT/output', 'a rewrite handler with output answers with it', %w[nowait sleep sub_request],
   'HTTP/1.1 200 OK', 'output'],
  ['/content/WAIT/ok', 'a content handler that returns Nginx::OK without output answers 200 with an empty body',
   %w[nowait sleep], 'HTTP/1.1 200 OK', ''],
  ['/content/WAIT/output', 'a content handler with output answers with it', %w[nowait sleep],
   'HTTP/1.1 200 OK', 'output'],
  ['/content/WAIT/forbidden', 'a content handler that returns 403 answers 403', %w[nowait sleep],
   'HTTP/1.1 403 Forbidden', '<title>403 Forbidden</title>'],
].each do |path, what, waits, line, body|
  waits.each do |wait|
    t.assert('async', "after a server rewrite handler returned Nginx::DECLINED, #{what} #{ASYNC_ISOLATION_WAITS[wait]}") do
      status, raw = tcp_client(18179, "GET #{path.sub("WAIT", wait)} HTTP/1.1\r\nHost: localhost\r\n\r\n" \
                                      "GET /rewrite/nowait/declined HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
      responses = async_isolation_responses(raw)
      t.assert_equal 'EOF', status
      t.assert_equal 2, responses.size
      t.assert_equal line, responses[0].to_a[0]
      if body.start_with?('<title>')
        t.assert_include responses[0].to_a[1].to_s, body
      else
        t.assert_equal body, responses[0].to_a[1]
      end
      t.assert_equal 'HTTP/1.1 200 OK', responses[1].to_a[0]
      t.assert_equal "passed\n", responses[1].to_a[1]
    end
  end
end

t.report
