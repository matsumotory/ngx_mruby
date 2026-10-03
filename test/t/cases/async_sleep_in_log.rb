# Nginx::Async in a log handler.
# Config: test/conf/conf.d/52-async-sleep-in-log.conf (port 18129).
#
# The log handler runs after the response was sent, so the client gets the
# response of the content handler either way. The cases read error.log for
# the error line of the log handler and for "[alert]" lines. A timer that
# outlived the request would call ngx_http_finalize_request on the freed
# request when it expires, which can log an "[alert] ... finalize non-active
# request" line; under valgrind or AddressSanitizer it shows as invalid reads
# and writes. test.sh builds nginx with --with-debug and the test config logs
# at debug level, so ngx_http_subrequest writes an 'http subrequest "/leaf?"'
# line for each subrequest it creates.

t = SimpleTest.new "ngx_mruby test: Nginx::Async in a log handler"

def async_log_split(raw)
  head, body = raw.split("\r\n\r\n", 2)
  [head.to_s.split("\r\n")[0].to_s, body.to_s]
end

def async_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

# Lines that nginx appended to error.log after offset.
def async_log_lines(offset)
  File.open(async_log_path) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
end

t.assert('async', 'Nginx::Async.sleep in a log handler raises and leaves no timer behind') do
  offset = File.size(async_log_path)

  status, raw = tcp_client(18129, "GET /log_sleep HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_log_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'ok', body

  # Lasts longer than the sleep of the log handler above.
  status, raw = tcp_client(18129, "GET /wait HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_log_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'waited', body

  lines = async_log_lines(offset)
  raised = lines.select { |l| l.include?('[error]') && l.include?('Nginx::Async.sleep is not available in a log handler') }
  t.assert_equal 1, raised.size
  alerts = lines.select { |l| l.include?('[alert]') }
  t.assert_equal [], alerts
end

t.assert('async', 'Nginx::Async::HTTP.sub_request in a log handler raises and starts no subrequest') do
  offset = File.size(async_log_path)

  status, raw = tcp_client(18129, "GET /log_sub_request HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_log_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'ok', body

  # The location of the subrequest still answers a request of its own.
  status, raw = tcp_client(18129, "GET /leaf HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_log_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'leaf', body

  lines = async_log_lines(offset)
  raised = lines.select do |l|
    l.include?('[error]') && l.include?('Nginx::Async::HTTP.sub_request is not available in a log handler')
  end
  t.assert_equal 1, raised.size
  subrequests = lines.select { |l| l.include?('http subrequest "/leaf') }
  t.assert_equal [], subrequests
  alerts = lines.select { |l| l.include?('[alert]') }
  t.assert_equal [], alerts
end

t.assert('async', 'Fiber.yield in a log handler ends the handler with an error line, and nginx keeps serving') do
  offset = File.size(async_log_path)

  status, raw = tcp_client(18129, "GET /log_yield HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_log_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'ok', body

  status, raw = tcp_client(18129, "GET /leaf HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_log_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'leaf', body

  lines = async_log_lines(offset)
  yielded = lines.select { |l| l.include?('[error]') && l.include?('a log handler yielded its fiber') }
  t.assert_equal 1, yielded.size
  alerts = lines.select { |l| l.include?('[alert]') }
  t.assert_equal [], alerts
end

t.report
