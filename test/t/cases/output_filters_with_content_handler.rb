# An mruby content handler and the mruby output filters in the same location
# (issue #206).
# Config: test/conf/conf.d/54-output-filters-with-content-handler.conf
# (port 18138).
#
# The content and rewrite handlers write "origin" with Nginx.rputs. Two
# locations serve a static file with a body filter that also calls
# Nginx.rputs, and one of them has a log handler. In one more location an
# access handler writes with Nginx.rputs and answers 403, and nginx sends its
# 403 page through both filters at a limited rate. The header filters count
# their runs in the X-Header-Filter-Runs response header, and the body
# filters turn the body to upper case. Each request is an HTTP/1.0 request
# through tcp_client, which reads until nginx closes the connection or its
# time limit passes, so a request that nginx never answers fails instead of
# blocking the run. The cases whose nginx stays up on 2.7.0 come first: the
# test nginx runs as one process, so a crash ends every later request.

t = SimpleTest.new "ngx_mruby test: output filters with a content handler"

def output_filters_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

# Sends GET path and returns the status of the connection, the status line,
# the response headers (names in lower case), the body, the [alert] lines
# that nginx wrote to error.log while it handled the request, and the number
# of error.log lines that contain marker. error.log is read line by line:
# the test config logs at debug level, and a request that runs its handlers
# again and again writes megabytes of lines.
def output_filters_request(path, marker = nil)
  offset = File.size(output_filters_log_path)
  status, raw = tcp_client(18138, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
  head, body = raw.split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  headers = {}
  lines[1..-1].to_a.each do |line|
    name, value = line.split(": ", 2)
    headers[name.downcase] = value
  end
  alerts = []
  marked = 0
  File.open(output_filters_log_path) do |f|
    f.seek(offset)
    while (line = f.gets)
      alerts << line.chomp if line.include?('[alert]')
      marked += 1 if marker && line.include?(marker)
    end
  end
  [status, lines[0].to_s, headers, body.to_s, alerts, marked]
end

t.assert('output filters', 'a header filter on a static file adds its header once') do
  status, line, headers, body, alerts = output_filters_request('/output_filters_static.txt')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal '1', headers['x-header-filter-runs']
  t.assert_equal "static file\n", body
  t.assert_equal '12', headers['content-length']
  t.assert_equal [], alerts
end

t.assert('output filters', 'a body filter after an Nginx.rputs content handler') do
  status, line, headers, body, alerts = output_filters_request('/content_and_body_filter')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'ORIGIN', body
  t.assert_equal '6', headers['content-length']
  t.assert_nil headers['x-header-filter-runs']
  t.assert_equal [], alerts
end

t.assert('output filters', 'Nginx.rputs in a body filter after a header filter sends nothing') do
  status, line, headers, body, alerts = output_filters_request('/static_body_filter_rputs')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal '1', headers['x-header-filter-runs']
  t.assert_equal "STATIC FILE\n", body
  t.assert_equal '12', headers['content-length']
  t.assert_equal [], alerts
end

t.assert('output filters', 'Nginx.rputs in a body filter after a header filter, then a log handler') do
  # The marker is the line that the log handler writes. nginx also logs the
  # code of the handler, which has #{...} where the marker has the URI.
  status, line, headers, body, alerts, marked = output_filters_request('/static_body_filter_rputs_log',
                                                                       'log handler ran for /static_body_filter_rputs_log')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal '1', headers['x-header-filter-runs']
  t.assert_equal "STATIC FILE\n", body
  t.assert_equal '12', headers['content-length']
  t.assert_equal [], alerts
  t.assert_equal 1, marked
end

t.assert('output filters', 'the 403 page after Nginx.rputs and Nginx.return 403, sent in several writes') do
  # The location has server_tokens off, so the page does not depend on the
  # nginx version. It is longer than the limit_rate of the location (100
  # bytes per second), so nginx needs more than one write to send it.
  page = "<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n" \
         "<center><h1>403 Forbidden</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
  status, line, headers, body, alerts, marked = output_filters_request('/deny_rputs_slow',
                                                                       'log handler ran for /deny_rputs_slow')
  t.assert_true page.bytesize > 100
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 403 Forbidden', line
  t.assert_equal '1', headers['x-header-filter-runs']
  t.assert_equal page.upcase, body
  t.assert_equal page.bytesize.to_s, headers['content-length']
  t.assert_equal [], alerts
  t.assert_equal 1, marked
end

t.assert('output filters', 'a header filter after an Nginx.rputs content handler runs once') do
  status, line, headers, body, alerts = output_filters_request('/content_and_header_filter')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal '1', headers['x-header-filter-runs']
  t.assert_equal 'origin', body
  t.assert_equal '6', headers['content-length']
  t.assert_equal [], alerts
end

t.assert('output filters', 'a header filter and a body filter after an Nginx.rputs content handler') do
  status, line, headers, body, alerts = output_filters_request('/content_and_both_filters')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal '1', headers['x-header-filter-runs']
  t.assert_equal 'ORIGIN', body
  t.assert_equal '6', headers['content-length']
  t.assert_equal [], alerts
end

t.assert('output filters', 'a header filter after an Nginx.rputs rewrite handler runs once') do
  status, line, headers, body, alerts = output_filters_request('/rewrite_and_header_filter')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal '1', headers['x-header-filter-runs']
  t.assert_equal 'origin', body
  t.assert_equal '6', headers['content-length']
  t.assert_equal [], alerts
end

t.report
