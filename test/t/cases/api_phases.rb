# Where the methods of the Ruby API work (section 2.1 of
# docs/proposals/core-alpha1.md): a method called in a handler where it has
# no effect raises a RuntimeError that names the method and the handler.
# Config: test/conf/conf.d/98-api-phases.conf (port 18119).
#
# A request is sent with HTTP/1.0, and tcp_client returns when nginx closed
# the connection, after the log phase. Each call of the hooks writes the line
# "api_phases KIND NAME: RESULT" to error.log (see the config).

t = SimpleTest.new "ngx_mruby test: where the methods of the Ruby API work"

def api_phases_error_log
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

# Sends GET path and returns [status line, headers, body, error.log lines of
# the request].
def api_phases_get(path)
  offset = File.size(api_phases_error_log)
  status, raw = tcp_client(18119, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
  head, body = raw.split("\r\n\r\n", 2)
  lines = File.open(api_phases_error_log) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
  head_lines = head.to_s.split("\r\n")
  [status, head_lines[0].to_s, head_lines[1..-1] || [], body.to_s, lines]
end

# The result that the hooks logged for each call of the handler kind, by name.
def api_phases_results(lines, kind)
  results = {}
  prefix = "api_phases #{kind} "
  lines.each do |l|
    next unless l.include?('[error]')

    i = l.index(prefix)
    next unless i

    name, result = l[(i + prefix.size)..-1].split(': ', 2)
    # nginx appends ", client: ..." to a line of a request, and in the log
    # phase " while logging request" before it
    result = result.to_s.split(', client: ', 2)[0].to_s
    suffix = ' while logging request'
    if result.size >= suffix.size && result[(result.size - suffix.size)..-1] == suffix
      result = result[0, result.size - suffix.size]
    end
    results[name] = result
  end
  results
end

def api_phases_raised(name, where)
  "RuntimeError: #{name} is not available in #{where}"
end

t.assert('api phases', 'a log handler raises for the methods that change the request, the response head and the output') do
  status, line, _head, body, lines = api_phases_get('/log')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'log', body
  results = api_phases_results(lines, 'log')
  where = 'a log handler'
  t.assert_equal 'ok', results['uri']
  t.assert_equal 'ok', results['var=']
  t.assert_equal api_phases_raised('Nginx::Request#uri=', where), results['uri=']
  t.assert_equal api_phases_raised('Nginx::Request#args=', where), results['args=']
  t.assert_equal api_phases_raised('Nginx::Headers_in#[]=', where), results['headers_in[]=']
  t.assert_equal api_phases_raised('Nginx::Headers_in#delete', where), results['headers_in.delete']
  t.assert_equal api_phases_raised('Nginx::Headers_out#[]=', where), results['headers_out[]=']
  t.assert_equal api_phases_raised('Nginx::Headers_out#delete', where), results['headers_out.delete']
  t.assert_equal api_phases_raised('Nginx.status_code=', where), results['status_code=']
  t.assert_equal api_phases_raised('Nginx.return', where), results['return']
  t.assert_equal api_phases_raised('Nginx::Request#content_type=', where), results['content_type=']
  t.assert_equal api_phases_raised('Nginx.rputs', where), results['rputs']
  t.assert_equal api_phases_raised('Nginx.echo', where), results['echo']
  t.assert_equal 'RuntimeError: Nginx::Filter#body can only be used in an output body filter', results['Filter#body']
end

t.assert('api phases', 'a log handler that sets headers_out ends with the exception, and the response stays') do
  status, line, _head, body, lines = api_phases_get('/log_raise')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'log', body
  raised = lines.select do |l|
    l.include?('#<RuntimeError: Nginx::Headers_out#[]= is not available in a log handler>')
  end
  t.assert_equal 1, raised.size
end

t.assert('api phases', 'a header filter changes the response head, and raises for the request and the output') do
  status, line, head, body, lines = api_phases_get('/header_filter')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_include head, 'X-Api-Phases: header_filter'
  t.assert_equal 'origin', body
  results = api_phases_results(lines, 'header_filter')
  where = 'a header filter'
  t.assert_equal 'ok', results['uri']
  t.assert_equal 'ok', results['headers_out[]=']
  t.assert_equal api_phases_raised('Nginx::Request#uri=', where), results['uri=']
  t.assert_equal api_phases_raised('Nginx::Headers_in#[]=', where), results['headers_in[]=']
  t.assert_equal api_phases_raised('Nginx.rputs', where), results['rputs']
  t.assert_equal 'RuntimeError: Nginx::Filter#body can only be used in an output body filter', results['Filter#body']
end

t.assert('api phases', 'Nginx.rputs in a header filter ends the filter with the exception and status 500') do
  status, line, _head, body, lines = api_phases_get('/header_filter_raise')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_equal 'origin', body
  raised = lines.select { |l| l.include?('#<RuntimeError: Nginx.rputs is not available in a header filter>') }
  t.assert_equal 1, raised.size
end

t.assert('api phases', 'a body filter changes the response head and the body, and raises for the request') do
  status, line, head, body, lines = api_phases_get('/body_filter')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_include head, 'X-Api-Phases: body_filter'
  t.assert_equal 'filtered:origin', body
  results = api_phases_results(lines, 'body_filter')
  where = 'a body filter'
  t.assert_equal 'ok', results['uri']
  t.assert_equal 'ok', results['headers_out[]=']
  t.assert_equal 'ok', results['Filter#body']
  t.assert_equal 'ok', results['Filter#body=']
  t.assert_equal api_phases_raised('Nginx::Request#method=', where), results['method=']
  t.assert_equal api_phases_raised('Nginx::Headers_in#delete', where), results['headers_in.delete']
end

t.assert('api phases', 'an mruby_set handler changes the request and the response head, and raises for the output') do
  status, line, head, body, lines = api_phases_get('/set')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_include head, 'X-Api-Phases: set'
  t.assert_equal 'set:set', body
  results = api_phases_results(lines, 'set')
  where = 'an mruby_set handler'
  t.assert_equal 'ok', results['headers_in[]=']
  t.assert_equal 'ok', results['headers_out[]=']
  t.assert_equal api_phases_raised('Nginx.rputs', where), results['rputs']
  t.assert_equal api_phases_raised('Nginx.echo', where), results['echo']
  t.assert_equal 'RuntimeError: Nginx::Filter#output can only be used in an output body filter', results['Filter#output']
end

t.assert('api phases', 'a content handler uses every row but the body of a body filter') do
  status, line, head, body, lines = api_phases_get('/content')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_include head, 'X-Api-Phases: content'
  t.assert_include head, 'Content-Type: text/x-api-phases'
  t.assert_equal 'content:a=1', body
  results = api_phases_results(lines, 'content')
  t.assert_equal 'ok', results['args=']
  t.assert_equal 'ok', results['headers_out[]=']
  t.assert_equal 'ok', results['content_type=']
  t.assert_equal 'ok', results['rputs']
  t.assert_equal 'RuntimeError: Nginx::Filter#body can only be used in an output body filter', results['Filter#body']
end

t.assert('api phases', 'after nginx has sent the response header, the methods of the response head raise') do
  status, line, head, body, lines = api_phases_get('/post_action')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal [], head.select { |h| h.start_with?('X-Api-Phases') }
  t.assert_equal 'post_action', body
  results = api_phases_results(lines, 'post_action')
  t.assert_equal 'ok', results['uri']
  t.assert_equal 'RuntimeError: Nginx::Headers_out#[]= is not available after the response header is sent', results['headers_out[]=']
  t.assert_equal 'RuntimeError: Nginx.return is not available after the response header is sent', results['return']
end

t.report
