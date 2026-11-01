# An mruby_set handler that waits in Nginx::Async.sleep sets its variable,
# and the request goes on as without the wait: the status that the code sets
# with Nginx.return does not end the handler, and an exception after the
# sleep answers 500 (without a wait, the variable is empty then).
# Config: test/conf/conf.d/83-async-set-var.conf (port 18182) and
# test/html/async_set_var.rb.

t = SimpleTest.new "ngx_mruby test: an mruby_set handler that waits"

# Splits the bytes of pipelined responses into [status line, body] pairs,
# using Content-Length.
def async_set_var_responses(raw)
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

ASYNC_SET_VAR_WAITS = {
  'nowait' => 'without a wait',
  'sleep' => 'after Nginx::Async.sleep',
  'sleep_twice' => 'after two calls of Nginx::Async.sleep',
}

# [path, what, the waits, [status line, body (or the title of nginx's error
# page), whether the next request on the connection is answered]]. After a
# 500, nginx closes the connection.
[
  ['/set/WAIT/value', 'sets its variable for the content handler', %w[nowait sleep sleep_twice],
   ['HTTP/1.1 200 OK', 'value=set', true]],
  ['/set/WAIT/forbidden', 'that sets 403 with Nginx.return sets its variable, and the status does not end the request',
   %w[nowait sleep], ['HTTP/1.1 200 OK', 'value=set', true]],
  ['/proxy/WAIT/value', 'sets its variable for proxy_pass', %w[nowait sleep], ['HTTP/1.1 200 OK', 'echo=v=set', true]],
  ['/set/nowait/raise', 'that raises without a wait leaves its variable empty', %w[nowait],
   ['HTTP/1.1 200 OK', 'value=', true]],
  ['/set/WAIT/raise', 'that raises after the sleep answers 500', %w[sleep],
   ['HTTP/1.1 500 Internal Server Error', '<title>500 Internal Server Error</title>', false]],
  # Nginx::Async::HTTP.sub_request raises a RuntimeError in an mruby_set
  # handler: without a wait the variable is empty, as after any exception
  # there, and after a sleep the request gets 500
  ['/set/nowait/sub_request', 'that calls Nginx::Async::HTTP.sub_request gets a RuntimeError and leaves its variable empty',
   %w[nowait], ['HTTP/1.1 200 OK', 'value=', true]],
  ['/set/WAIT/sub_request', 'that calls Nginx::Async::HTTP.sub_request after the sleep gets a RuntimeError and answers 500',
   %w[sleep], ['HTTP/1.1 500 Internal Server Error', '<title>500 Internal Server Error</title>', false]],
  # a value that cannot be converted to a String answers 500
  ['/set/WAIT/to_s_raises', 'whose value cannot be converted to a String answers 500', %w[nowait sleep],
   ['HTTP/1.1 500 Internal Server Error', '<title>500 Internal Server Error</title>', false]],
].each do |path, what, waits, expected|
  line, body, keeps = expected
  waits.each do |wait|
    t.assert('async', "an mruby_set handler #{what} #{ASYNC_SET_VAR_WAITS[wait]}") do
      status, raw = tcp_client(18182, "GET #{path.sub("WAIT", wait)} HTTP/1.1\r\nHost: localhost\r\n\r\n" \
                                      "GET /plain HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
      responses = async_set_var_responses(raw)
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
        t.assert_equal 'plain', responses[1].to_a[1]
      else
        t.assert_equal 1, responses.size
      end
    end
  end
end

t.assert('async', 'error.log names the RuntimeError of Nginx::Async::HTTP.sub_request in an mruby_set handler, and the worker answers the next request') do
  path = File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
  log = File.open(path) do |f|
    f.seek([File.size(path) - 1_000_000, 0].max)
    f.read
  end
  t.assert_true log.include?('Nginx::Async::HTTP.sub_request is not available in an mruby_set handler'),
                'error.log has the message of the RuntimeError'
  t.assert_true log.include?('raised in to_s'), 'error.log has the exception of to_s'
  status, raw = tcp_client(18182, "GET /plain HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
  t.assert_equal 'EOF', status
  t.assert_equal ['HTTP/1.1 200 OK', 'plain'], async_set_var_responses(raw)[0]
end

t.report
