# A handler ends in the same way with or without a wait: for each phase that
# can wait, pairs of requests whose handler ends in the same way, once
# without a wait and once after Nginx::Async.sleep 1 (and, for rewrite and
# server rewrite handlers, after Nginx::Async::HTTP.sub_request). Each pair
# gets the same status and body, and the next request on the connection is
# answered (after a 500, nginx closes the connection, with or without a
# wait).
# Config: test/conf/conf.d/82-async-resume-result.conf (ports 18176, 18177
# and 18178) and test/html/async_resume_result.rb.
#
# The cases list only the ends that are already the same with and without a
# wait. The proposal docs/proposals/core-stabilization.md (section 8) adds the
# others with the changes that make them the same.

t = SimpleTest.new "ngx_mruby test: a handler ends in the same way with or without a wait"

# Splits the bytes of pipelined responses into [status line, body] pairs,
# using Content-Length.
def async_resume_responses(raw)
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

ASYNC_RESUME_ENDS = {
  'declined' => ['HTTP/1.1 200 OK', "passed\n", true],
  'forbidden' => ['HTTP/1.1 403 Forbidden', '<title>403 Forbidden</title>', true],
  'output' => ['HTTP/1.1 200 OK', 'output', true],
  'raise' => ['HTTP/1.1 500 Internal Server Error', '<title>500 Internal Server Error</title>', false],
  'ok' => ['HTTP/1.1 200 OK', '', true],
  'none' => ['HTTP/1.1 200 OK', '', true],
}

ASYNC_RESUME_WAITS = {
  'nowait' => 'without a wait',
  'sleep' => 'after Nginx::Async.sleep',
  'sub_request' => 'after Nginx::Async::HTTP.sub_request',
}

# [port, location, handler, the ends, the waits, the path of the next request]
[
  [18176, 'rewrite', 'a rewrite handler', %w[declined forbidden output raise], %w[nowait sleep sub_request], '/plain/x'],
  [18176, 'access_all', 'an access handler under satisfy all', %w[declined forbidden raise], %w[nowait sleep], '/plain/x'],
  [18176, 'access_any', 'an access handler under satisfy any', %w[forbidden raise], %w[nowait sleep], '/plain/x'],
  [18176, 'content', 'a content handler', %w[none declined ok forbidden output raise], %w[nowait sleep], '/plain/x'],
  [18177, 'server_rewrite', 'a server rewrite handler', %w[declined forbidden output raise], %w[nowait sleep sub_request], '/x/nowait/declined'],
  [18178, 'post_read', 'a post_read handler', %w[declined forbidden raise], %w[nowait sleep], '/x/nowait/declined'],
].each do |port, location, handler, ends, waits, next_path|
  ends.each do |ending|
    line, body, keeps = ASYNC_RESUME_ENDS[ending]
    # Under satisfy any, deny all refuses the request that the mruby handler
    # passes on with Nginx::DECLINED.
    line, body = 'HTTP/1.1 403 Forbidden', '<title>403 Forbidden</title>' if location == 'access_any' && ending == 'declined'
    # Nginx::DECLINED in a content handler goes on to the static module, which
    # finds no file for the URI.
    line, body = 'HTTP/1.1 404 Not Found', '<title>404 Not Found</title>' if location == 'content' && ending == 'declined'
    waits.each do |wait|
      t.assert('async', "#{handler} that ends with #{ending} answers in the same way #{ASYNC_RESUME_WAITS[wait]}") do
        status, raw = tcp_client(port, "GET /#{location}/#{wait}/#{ending} HTTP/1.1\r\nHost: localhost\r\n\r\n" \
                                       "GET #{next_path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        responses = async_resume_responses(raw)
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
end

t.report
