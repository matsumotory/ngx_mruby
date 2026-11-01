# Nginx::Async::HTTP.sub_request returns the response of the subrequest, a
# content handler waits for a subrequest before and after Nginx::Async.sleep,
# and a handler that waits for a subrequest runs its code once and lets the
# request go on.
# Config: test/conf/conf.d/84-async-subrequest-return.conf (ports 18183 and
# 18184) and test/html/async_subrequest_once*.rb.

t = SimpleTest.new "ngx_mruby test: Nginx::Async::HTTP.sub_request returns the response"

# Splits the bytes of pipelined responses into [status line, body] pairs,
# using Content-Length.
def async_subrequest_responses(raw)
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

def async_subrequest_get(port, path, next_path)
  status, raw = tcp_client(port, "GET #{path} HTTP/1.1\r\nHost: localhost\r\n\r\n" \
                                 "GET #{next_path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
  [status, async_subrequest_responses(raw)]
end

t.assert('async', 'Nginx::Async::HTTP.sub_request returns the response, the same as last_response') do
  status, responses = async_subrequest_get(18183, '/return', '/plain')
  t.assert_equal 'EOF', status
  t.assert_equal ['HTTP/1.1 200 OK', 'Nginx::Async::HTTP::Response:200:leaf:true'], responses[0]
  t.assert_equal ['HTTP/1.1 200 OK', 'plain'], responses[1]
end

{
  '/content_sub_request' => 'a content handler that waits for a subrequest',
  '/content_sleep_then_sub_request' => 'a content handler that sleeps and then waits for a subrequest',
  '/content_sub_request_then_sleep' => 'a content handler that waits for a subrequest and then sleeps',
}.each do |path, what|
  t.assert('async', "#{what} answers with its body, and the next request on the connection is answered") do
    status, responses = async_subrequest_get(18183, path, '/plain')
    t.assert_equal 'EOF', status
    t.assert_equal 2, responses.size
    t.assert_equal ['HTTP/1.1 200 OK', 'got:200:leaf'], responses[0]
    t.assert_equal ['HTTP/1.1 200 OK', 'plain'], responses[1]
  end
end

t.assert('async', 'no [alert] line for the content handlers that wait for a subrequest') do
  # the end of the log, where the lines of these requests are
  path = File.join(ENV['NGINX_INSTALL_DIR'], 'logs/error.log')
  log = File.open(path) do |f|
    f.seek([File.size(path) - 4_000_000, 0].max)
    f.read
  end
  alerts = log.split("\n").select { |l| l.include?('[alert]') && l.include?('/content_s') }
  t.assert_equal [], alerts
end

# [port, path, the handler]. The content handler that runs after the
# handler reports runs=<runs of the code> subs=<subrequests>.
[
  [18183, '/once_access/none', 'an access handler that waits for a subrequest and sets no result', '/plain'],
  [18183, '/once_access/declined', 'an access handler that waits for a subrequest and returns Nginx::DECLINED', '/plain'],
  [18184, '/once_post_read/none', 'a post_read handler that waits for a subrequest and sets no result', '/after'],
  [18184, '/once_post_read/declined', 'a post_read handler that waits for a subrequest and returns Nginx::DECLINED', '/after'],
].each do |port, path, what, next_path|
  t.assert('async', "#{what} runs once, its subrequest runs once, and the request goes on") do
    status, responses = async_subrequest_get(port, path, next_path)
    t.assert_equal 'EOF', status
    t.assert_equal 2, responses.size
    t.assert_equal ['HTTP/1.1 200 OK', 'runs=1 subs=1'], responses[0]
    t.assert_equal 'HTTP/1.1 200 OK', responses[1].to_a[0]
  end
end

t.report
