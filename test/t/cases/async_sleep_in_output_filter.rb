# Nginx::Async in the output filters.
# Config: test/conf/conf.d/53-async-sleep-in-output-filter.conf (port 18131).
#
# Each location sends its own response with return, and its filter calls
# Nginx::Async or Fiber.yield. The cases check that the client gets status
# 500 with the unfiltered body "origin", and the line in error.log.
# test.sh builds nginx with --with-debug and the test config logs at debug
# level, so ngx_http_subrequest writes an 'http subrequest "/filter_leaf?"'
# line for each subrequest it creates.

t = SimpleTest.new "ngx_mruby test: Nginx::Async in the output filters"

def async_filter_split(raw)
  head, body = raw.split("\r\n\r\n", 2)
  [head.to_s.split("\r\n")[0].to_s, body.to_s]
end

def async_filter_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

# Lines that nginx appended to error.log after offset.
def async_filter_lines(offset)
  File.open(async_filter_path) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
end

def async_filter_request(path)
  offset = File.size(async_filter_path)
  status, raw = tcp_client(18131, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_filter_split(raw)
  [status, line, body, async_filter_lines(offset)]
end

t.assert('async', 'Nginx::Async.sleep in a header filter raises') do
  status, line, body, lines = async_filter_request('/header_filter_sleep')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_equal 'origin', body
  raised = lines.select { |l| l.include?('[error]') && l.include?('Nginx::Async.sleep is not available in a header filter') }
  t.assert_equal 1, raised.size
end

t.assert('async', 'Nginx::Async.sleep in a body filter raises') do
  status, line, body, lines = async_filter_request('/body_filter_sleep')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_equal 'origin', body
  raised = lines.select { |l| l.include?('[error]') && l.include?('Nginx::Async.sleep is not available in a body filter') }
  t.assert_equal 1, raised.size
end

t.assert('async', 'Fiber.yield in a header filter ends the filter with status 500') do
  status, line, body, lines = async_filter_request('/header_filter_yield')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_equal 'origin', body
  yielded = lines.select { |l| l.include?('[error]') && l.include?('a header filter yielded') }
  t.assert_equal 1, yielded.size
end

t.assert('async', 'Fiber.yield in a body filter ends the filter with status 500') do
  status, line, body, lines = async_filter_request('/body_filter_yield')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_equal 'origin', body
  yielded = lines.select { |l| l.include?('[error]') && l.include?('a body filter yielded') }
  t.assert_equal 1, yielded.size
end

t.assert('async', 'Nginx::Async::HTTP.sub_request in a header filter raises and starts no subrequest') do
  status, line, body, lines = async_filter_request('/header_filter_sub_request')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_equal 'origin', body
  raised = lines.select do |l|
    l.include?('[error]') && l.include?('Nginx::Async::HTTP.sub_request is not available in a header filter')
  end
  t.assert_equal 1, raised.size
  subrequests = lines.select { |l| l.include?('http subrequest "/filter_leaf') }
  t.assert_equal [], subrequests
end

t.report
