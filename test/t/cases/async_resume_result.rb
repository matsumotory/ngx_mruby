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
# Every handler has every end, without a wait, after Nginx::Async.sleep and
# after Nginx::Async::HTTP.sub_request. Under satisfy any, a 403 lets nginx try the
# next access handler (allow all in /access_any_allow/), and an access
# handler that goes on is followed by auth_request in /access_auth/. A
# rewrite or server rewrite handler without a result, or with Nginx::OK, goes
# on to the next phase handler.

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

ASYNC_RESUME_ENDS = {
  'none' => ['HTTP/1.1 200 OK', "passed\n", true],
  'ok' => ['HTTP/1.1 200 OK', "passed\n", true],
  'declined' => ['HTTP/1.1 200 OK', "passed\n", true],
  'forbidden' => ['HTTP/1.1 403 Forbidden', '<title>403 Forbidden</title>', true],
  'output' => ['HTTP/1.1 200 OK', 'output', true],
  'raise' => ['HTTP/1.1 500 Internal Server Error', '<title>500 Internal Server Error</title>', false],
}

ASYNC_RESUME_WAITS = {
  'nowait' => 'without a wait',
  'sleep' => 'after Nginx::Async.sleep',
  'sub_request' => 'after Nginx::Async::HTTP.sub_request',
}

# [port, location, handler, the ends, the waits, the path of the next request]
[
  [18176, 'rewrite', 'a rewrite handler', %w[none declined ok forbidden output raise], %w[nowait sleep sub_request], '/plain/x'],
  [18176, 'access_all', 'an access handler under satisfy all', %w[none declined ok forbidden output raise], %w[nowait sleep sub_request], '/plain/x'],
  [18176, 'access_any', 'an access handler under satisfy any', %w[none declined ok forbidden output raise], %w[nowait sleep sub_request], '/plain/x'],
  [18176, 'access_any_allow', 'an access handler under satisfy any before allow all', %w[none declined ok forbidden output raise], %w[nowait sleep sub_request], '/plain/x'],
  [18176, 'access_auth', 'an access handler before auth_request', %w[none declined ok forbidden output raise], %w[nowait sleep sub_request], '/plain/x'],
  [18176, 'content', 'a content handler', %w[none declined ok forbidden output raise], %w[nowait sleep sub_request], '/plain/x'],
  [18177, 'server_rewrite', 'a server rewrite handler', %w[none declined ok forbidden output raise], %w[nowait sleep sub_request], '/x/nowait/declined'],
  [18178, 'post_read', 'a post_read handler', %w[none declined ok forbidden output raise], %w[nowait sleep sub_request], '/x/nowait/declined'],
].each do |port, location, handler, ends, waits, next_path|
  ends.each do |ending|
    line, body, keeps = ASYNC_RESUME_ENDS[ending]
    # A content handler that ends without output and without a status answers
    # 200 with an empty body (#574).
    line, body, keeps = 'HTTP/1.1 200 OK', '', true if location == 'content' && %w[none ok].include?(ending)
    # Under satisfy any, deny all refuses the request that the mruby handler
    # passes on with Nginx::DECLINED.
    line, body = 'HTTP/1.1 403 Forbidden', '<title>403 Forbidden</title>' if location == 'access_any' && ending == 'declined'
    # Under satisfy any, a 403 of the mruby handler lets nginx try the next
    # access handler, and allow all allows the request.
    line, body = 'HTTP/1.1 200 OK', "passed\n" if location == 'access_any_allow' && ending == 'forbidden'
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

t.assert('async', 'an access handler that calls Nginx.redirect ends with the answer of the target, and the next request is answered') do
  status, raw = tcp_client(18176, "GET /access_redirect HTTP/1.1\r\nHost: localhost\r\n\r\n" \
                                  "GET /plain/x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
  responses = async_resume_responses(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 2, responses.size
  t.assert_equal ['HTTP/1.1 200 OK', ''], responses[0]
  t.assert_equal ['HTTP/1.1 200 OK', "passed\n"], responses[1]
end

t.report
