# The result of a handler is its own: on a server whose server rewrite
# handler stores Nginx::DECLINED for every request, a later handler ends by
# the result it sets, with or without a wait.
# Config: test/conf/conf.d/82-async-result-isolation.conf (port 18179) and
# test/html/async_resume_result.rb.
#
# Access and content handlers have every end. Rewrite handlers list only the
# ends that the stored value does not decide; the proposal
# docs/proposals/core-stabilization.md (section 8) adds the end without a
# result with the change that lets them go on.

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
    # A response without Content-Length (a chunked one) would hide what
    # follows it: count it as a response that the cases do not expect.
    if length.nil?
      responses << ['no Content-Length: ' + lines[0].to_s, rest]
      break
    end
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

ASYNC_ISOLATION_FORBIDDEN = ['HTTP/1.1 403 Forbidden', '<title>403 Forbidden</title>', true]
ASYNC_ISOLATION_ERROR = ['HTTP/1.1 500 Internal Server Error', '<title>500 Internal Server Error</title>', false]
ASYNC_ISOLATION_PASSED = ['HTTP/1.1 200 OK', "passed\n", true]

# [path, what the later handler does, the waits, [status line, body (or the
# title of nginx's error page), whether the next request on the connection
# is answered]]. After a 500, nginx closes the connection.
[
  ['/access_all/WAIT/none', 'an access handler under satisfy all that sets no result goes on', %w[nowait sleep],
   ASYNC_ISOLATION_PASSED],
  ['/access_all/WAIT/ok', 'an access handler under satisfy all that returns Nginx::OK goes on', %w[nowait sleep],
   ASYNC_ISOLATION_PASSED],
  ['/access_all/WAIT/declined', 'an access handler under satisfy all that returns Nginx::DECLINED goes on', %w[nowait sleep],
   ASYNC_ISOLATION_PASSED],
  ['/access_all/WAIT/forbidden', 'an access handler under satisfy all that returns 403 answers 403', %w[nowait sleep],
   ASYNC_ISOLATION_FORBIDDEN],
  ['/access_all/WAIT/output', 'an access handler under satisfy all with output answers with it', %w[nowait sleep],
   ['HTTP/1.1 200 OK', 'output', true]],
  ['/access_all/WAIT/raise', 'an access handler under satisfy all that raises answers 500', %w[nowait sleep], ASYNC_ISOLATION_ERROR],
  ['/access_any/WAIT/none', 'an access handler under satisfy any that sets no result allows the request', %w[nowait sleep],
   ASYNC_ISOLATION_PASSED],
  ['/access_any/WAIT/ok', 'an access handler under satisfy any that returns Nginx::OK allows the request', %w[nowait sleep],
   ASYNC_ISOLATION_PASSED],
  ['/access_any/WAIT/forbidden', 'an access handler under satisfy any that returns 403 answers 403', %w[nowait sleep],
   ASYNC_ISOLATION_FORBIDDEN],
  ['/access_any/WAIT/raise', 'an access handler under satisfy any that raises answers 500', %w[nowait sleep], ASYNC_ISOLATION_ERROR],
  ['/rewrite/WAIT/declined', 'a rewrite handler that returns Nginx::DECLINED goes on', %w[nowait sleep sub_request],
   ASYNC_ISOLATION_PASSED],
  ['/rewrite/WAIT/forbidden', 'a rewrite handler that returns 403 answers 403', %w[nowait sleep sub_request],
   ASYNC_ISOLATION_FORBIDDEN],
  ['/rewrite/WAIT/output', 'a rewrite handler with output answers with it', %w[nowait sleep sub_request],
   ['HTTP/1.1 200 OK', 'output', true]],
  ['/rewrite/WAIT/raise', 'a rewrite handler that raises answers 500', %w[nowait sleep sub_request], ASYNC_ISOLATION_ERROR],
  ['/content/WAIT/none', 'a content handler that sets no result and writes no output answers 200 with an empty body',
   %w[nowait sleep], ['HTTP/1.1 200 OK', '', true]],
  ['/content/WAIT/ok', 'a content handler that returns Nginx::OK without output answers 200 with an empty body',
   %w[nowait sleep], ['HTTP/1.1 200 OK', '', true]],
  ['/content/WAIT/declined', 'a content handler that returns Nginx::DECLINED goes on to the static module, which answers 404',
   %w[nowait sleep], ['HTTP/1.1 404 Not Found', '<title>404 Not Found</title>', true]],
  ['/content/WAIT/output', 'a content handler with output answers with it', %w[nowait sleep], ['HTTP/1.1 200 OK', 'output', true]],
  ['/content/WAIT/forbidden', 'a content handler that returns 403 answers 403', %w[nowait sleep], ASYNC_ISOLATION_FORBIDDEN],
  ['/content/WAIT/raise', 'a content handler that raises answers 500', %w[nowait sleep], ASYNC_ISOLATION_ERROR],
].each do |path, what, waits, expected|
  line, body, keeps = expected
  waits.each do |wait|
    t.assert('async', "after a server rewrite handler returned Nginx::DECLINED, #{what} #{ASYNC_ISOLATION_WAITS[wait]}") do
      status, raw = tcp_client(18179, "GET #{path.sub("WAIT", wait)} HTTP/1.1\r\nHost: localhost\r\n\r\n" \
                                      "GET /rewrite/nowait/declined HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
      responses = async_isolation_responses(raw)
      t.assert_equal 'EOF', status
      t.assert_equal line, responses[0].to_a[0]
      if body.start_with?('<title>')
        t.assert_include responses[0].to_a[1].to_s, body
      else
        t.assert_equal body, responses[0].to_a[1]
      end
      if keeps
        t.assert_equal 2, responses.size
        t.assert_equal 'HTTP/1.1 200 OK', responses[1].to_a[0]
        t.assert_equal "passed\n", responses[1].to_a[1]
      else
        t.assert_equal 1, responses.size
      end
    end
  end
end

t.report
