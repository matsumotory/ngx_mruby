# Arguments of the wrong type to Nginx.redirect (its status code) and to
# add_listener (the :address of its Hash), HTTP and stream.
# Config: test/conf/conf.d/96-argument-types.conf (port 18092). nginx_t is in
# test/t/cases/_prelude.rb.
#
# The status code of a redirect to a URL must be an Integer: another value
# raises TypeError, as a status code of the wrong type does in mruby. An
# internal redirect has no status code and ignores the second argument, as it
# did before. The :address of add_listener must be a String: a missing
# :address or another value raises TypeError, and nginx stops reading the
# configuration with that exception.
#
# Before the fix, Nginx.redirect read a status code of another type as an
# Integer and answered with a status line that had no valid status, or with
# no response at all for nil; add_listener read the :address as a String and
# could end the nginx process while it read the configuration.

t = SimpleTest.new "ngx_mruby test: the status code of Nginx.redirect and the :address of add_listener"

ARGUMENT_TYPES_PORT = 18092

# The log and the output of nginx -t show an exception as its inspect, whose
# format depends on the bundled mruby: "message (TypeError)" with mruby 3 on
# 2.x, "#<TypeError: message>" with mruby 4.1 on next. The runner of the
# cases is built from the same mruby/ tree as nginx, so the cases build the
# expected text with TypeError#inspect of the runner.

# Returns the status of the connection, the status line, the response headers
# (names in lowercase) and the body.
def argument_types_get(path)
  status, raw = tcp_client(ARGUMENT_TYPES_PORT, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
  head, body = raw.split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  headers = {}
  lines[1..-1].to_a.each do |line|
    name, value = line.split(':', 2)
    headers[name.downcase] = value.to_s.strip
  end
  [status, lines[0].to_s, headers, body.to_s]
end

def argument_types_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

# The redirects that worked before keep working: a URL with no status code
# or an Integer, and an internal redirect with any second argument.
t.assert('argument types', 'Nginx.redirect to a URL without a status code answers 302') do
  status, line, headers, _ = argument_types_get('/redirect?to=url')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 302 Moved Temporarily', line
  t.assert_equal 'http://example.com/redirected', headers['location']
end

t.assert('argument types', 'Nginx.redirect to a URL with the Integer 301 answers 301') do
  status, line, headers, _ = argument_types_get('/redirect?to=url&code=301')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 301 Moved Permanently', line
  t.assert_equal 'http://example.com/redirected', headers['location']
end

%w[none 301 string float nil].each do |code|
  t.assert('argument types', "Nginx.redirect to an internal location ignores the second argument (#{code})") do
    path = code == 'none' ? '/redirect?to=internal' : "/redirect?to=internal&code=#{code}"
    status, line, headers, body = argument_types_get(path)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_nil headers['x-raised']
    t.assert_equal 'internal', body
  end
end

# A status code that is not an Integer: the call raises TypeError, the script
# rescues it, and no redirect is made.
{
  'string' => 'String cannot be converted to Integer',
  'float' => 'Float cannot be converted to Integer',
  'nil' => 'nil cannot be converted to Integer',
}.each do |code, message|
  t.assert('argument types', "Nginx.redirect to a URL with a status code of the wrong type (#{code}) raises TypeError") do
    status, line, headers, body = argument_types_get("/redirect?to=url&code=#{code}")
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_nil headers['location']
    t.assert_equal "raised: TypeError: #{message}", headers['x-raised']
    t.assert_equal 'no redirect', body
  end
end

# Without a rescue in the script, the TypeError ends the rewrite handler as
# any exception does: the request gets 500 and error.log has the exception.
t.assert('argument types', 'Nginx.redirect with a status code of the wrong type answers 500 when the script does not rescue') do
  offset = File.size(argument_types_log_path)
  status, line, headers, body = argument_types_get('/redirect?to=url&code=string&rescue=no')
  log = File.open(argument_types_log_path) do |f|
    f.seek(offset)
    f.read.to_s
  end
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
  t.assert_nil headers['location']
  t.assert_include body, '<title>500 Internal Server Error</title>'
  t.assert_include log, TypeError.new('String cannot be converted to Integer').inspect
end

# Nginx.redirect takes one or two arguments. A third argument raises
# ArgumentError before the call does anything, for a URL and for an internal
# location. Before the fix, the format of the arguments did not match the
# number of variables that received them, and the result of a call with three
# arguments was not defined.
%w[url internal].each do |to|
  t.assert('argument types', "Nginx.redirect with three arguments (#{to}) raises ArgumentError") do
    status, line, headers, body = argument_types_get("/redirect?to=#{to}&code=three")
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_nil headers['location']
    t.assert_equal 'raised: ArgumentError: wrong number of arguments (given 3, expected 1..2)', headers['x-raised']
    t.assert_equal 'no redirect', body
  end
end

# The worker that got the values above still answers.
t.assert('argument types', 'the server answers after the status codes of the wrong type') do
  status, line, headers, _ = argument_types_get('/redirect?to=url&code=301')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 301 Moved Permanently', line
  t.assert_equal 'http://example.com/redirected', headers['location']
end

# add_listener runs while nginx reads the configuration, so nginx -t shows
# it. nginx -t does not open the listening sockets, so the address of the
# valid case is the port of the server above. The stream server has a
# return directive: nginx 1.26 rejects a stream server without a handler.
ARGUMENT_TYPES_LISTENERS = {
  'http' => lambda do |hash|
    "http {\n    server {\n        mruby_server_context_handler_code 'Nginx::Server.new.add_listener(#{hash})';\n    }\n}"
  end,
  'stream' => lambda do |hash|
    "stream {\n    server {\n        mruby_stream_server_context_code 'Nginx::Stream.add_listener(#{hash})';\n        return ok;\n    }\n}"
  end,
}

ARGUMENT_TYPES_LISTENERS.each do |kind, conf|
  t.assert('argument types', "#{kind} add_listener with a String :address passes nginx -t") do
    out = nginx_t(conf.call("{address: \"127.0.0.1:#{ARGUMENT_TYPES_PORT}\"}"))
    t.assert_include out, 'test is successful'
    t.assert_not_include out, 'TypeError'
  end

  {
    'an Integer :address' => ["{address: #{ARGUMENT_TYPES_PORT}}", 'Integer cannot be converted to String'],
    'a nil :address' => ['{address: nil}', 'nil cannot be converted to String'],
    'no :address' => ["{port: #{ARGUMENT_TYPES_PORT}}", 'nil cannot be converted to String'],
  }.each do |what, (hash, message)|
    t.assert('argument types', "#{kind} add_listener with #{what} fails nginx -t with TypeError") do
      out = nginx_t(conf.call(hash))
      t.assert_include out, 'mrb_run failed'
      t.assert_include out, TypeError.new(message).inspect
      t.assert_include out, 'test failed'
      t.assert_not_include out, 'test is successful'
    end
  end
end

t.report
