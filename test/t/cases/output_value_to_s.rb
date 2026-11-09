# The argument of Nginx.rputs, Nginx.echo, Nginx.redirect,
# Nginx::Filter#body= and Nginx::Filter#output when it is not a String.
# Config: test/conf/conf.d/88-output-value-to-s.conf (port 18191). Hook
# script: test/html/output_value_to_s.rb.
#
# ngx_mruby converts such an argument with to_s. When to_s is missing or
# raises, the call raises that exception. When to_s returns something other
# than a String, the call raises TypeError, as the setter of Nginx::Var does
# (test/t/cases/var_value_to_s.rb). The exception ends the handler like any
# other exception of the script: a rescue in the script catches it, and an
# exception that the script does not rescue gives 500 and goes to error.log.
#
# Before the fix, these methods read the result of to_s as a String without
# checking its type, and a to_s that returned an Integer could end the nginx
# process (test.sh runs a single process), so the cases after it got no
# answer. The cases with values that convert, or whose to_s is missing or
# raises, come first.

t = SimpleTest.new "ngx_mruby test: the argument of Nginx.rputs, Nginx.redirect and Nginx::Filter#body= as a String"

OUTPUT_VALUE_TO_S_PORT = 18191

def output_value_to_s_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

# Returns the status of the connection, the status line, the response
# headers (names in lowercase) and the body.
def output_value_to_s_get(path)
  status, raw = tcp_client(OUTPUT_VALUE_TO_S_PORT, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
  head, body = raw.split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  headers = {}
  lines[1..-1].to_a.each do |line|
    name, value = line.split(':', 2)
    headers[name.downcase] = value.to_s.strip
  end
  [status, lines[0].to_s, headers, body.to_s]
end

def output_value_to_s_path(call, value, rescue_it = true)
  location =
    case call
    when 'rputs', 'echo' then '/content'
    when 'redirect' then '/redirect'
    else '/filter'
    end
  path = "#{location}?call=#{call}&value=#{value}"
  path += '&rescue=no' unless rescue_it
  path
end

# What each call gives for a value that converts: rputs and echo write it
# (echo with a newline) and return, redirect answers 302 with it as the
# Location, and body= and output make it the body of the response.
[
  ['string', 'a String', 'http://example.com/string'],
  ['to_s_string', 'a value whose to_s returns a String', 'http://example.com/to_s'],
].each do |value, what, text|
  t.assert('output value to_s', "Nginx.rputs with #{what} writes it") do
    status, line, _, body = output_value_to_s_get(output_value_to_s_path('rputs', value))
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal "#{text}|returned", body
  end

  t.assert('output value to_s', "Nginx.echo with #{what} writes it with a newline") do
    status, line, _, body = output_value_to_s_get(output_value_to_s_path('echo', value))
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal "#{text}\n|returned", body
  end

  t.assert('output value to_s', "Nginx.redirect with #{what} answers 302 with it as the Location") do
    status, line, headers, _ = output_value_to_s_get(output_value_to_s_path('redirect', value))
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 302 Moved Temporarily', line
    t.assert_equal text, headers['location']
  end

  %w[body output].each do |call|
    t.assert('output value to_s', "Nginx::Filter##{call == 'body' ? 'body=' : 'output'} with #{what} makes it the body") do
      status, line, _, body = output_value_to_s_get(output_value_to_s_path(call, value))
      t.assert_equal 'EOF', status
      t.assert_equal 'HTTP/1.1 200 OK', line
      t.assert_equal text, body
    end
  end
end

# A value that does not convert: the call raises, the script rescues the
# exception, and the response shows it. Nothing of the value is written,
# no Location is set and the body of the static file is replaced only by
# the message of the exception.
def output_value_to_s_check_raised(t, value, what, raised, message)
  %w[rputs echo].each do |call|
    t.assert('output value to_s', "Nginx.#{call} with a value #{what} raises") do
      status, line, _, body = output_value_to_s_get(output_value_to_s_path(call, value))
      t.assert_equal 'EOF', status
      t.assert_equal 'HTTP/1.1 200 OK', line
      t.assert_true body.start_with?("|#{raised}"), "the call raised: #{body}"
      t.assert_include body, message
    end
  end

  t.assert('output value to_s', "Nginx.redirect with a value #{what} raises and does not redirect") do
    status, line, headers, body = output_value_to_s_get(output_value_to_s_path('redirect', value))
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_nil headers['location']
    t.assert_true headers['x-raised'].to_s.start_with?(raised), "the call raised: #{headers['x-raised']}"
    t.assert_include headers['x-raised'].to_s, message
    t.assert_equal 'no redirect', body
  end

  %w[body output].each do |call|
    t.assert('output value to_s', "Nginx::Filter##{call == 'body' ? 'body=' : 'output'} with a value #{what} raises") do
      status, line, _, body = output_value_to_s_get(output_value_to_s_path(call, value))
      t.assert_equal 'EOF', status
      t.assert_equal 'HTTP/1.1 200 OK', line
      t.assert_true body.start_with?(raised), "the call raised: #{body}"
      t.assert_include body, message
    end
  end
end

output_value_to_s_check_raised(t, 'no_to_s', 'without to_s', 'raised: NoMethodError: ', 'to_s')
output_value_to_s_check_raised(t, 'to_s_raises', 'whose to_s raises', 'raised: RuntimeError: ', 'raised in to_s')

# A to_s that returns something other than a String: TypeError, as for the
# setter of Nginx::Var. Before the fix, the first of these requests could end
# the nginx process.
offset = File.size(output_value_to_s_log_path)
output_value_to_s_check_raised(t, 'to_s_not_string', 'whose to_s does not return a String', 'raised: TypeError: ',
                               'cannot be converted to String')

# Without a rescue in the script, the TypeError ends the handler as any
# exception does: the request gets 500.
%w[rputs echo redirect].each do |call|
  t.assert('output value to_s', "Nginx.#{call} with a value whose to_s does not return a String answers 500 when the script does not rescue") do
    status, line, _, body = output_value_to_s_get(output_value_to_s_path(call, 'to_s_not_string', false))
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
    t.assert_include body, '<title>500 Internal Server Error</title>'
  end
end

# The bundled mruby 4.1 logs an exception as #<Class: message>; the case on
# 2.x looks for the format of mruby 3.
t.assert('output value to_s', 'error.log has the TypeError of the calls that the script did not rescue') do
  log = File.open(output_value_to_s_log_path) do |f|
    f.seek(offset)
    f.read.to_s
  end
  t.assert_include log, '#<TypeError: Integer cannot be converted to String>'
end

# Without a rescue in a body filter, the TypeError ends the filter as any
# exception there does: the response gets the status 500, and the value
# that body= or output was given does not replace the body of the file,
# which the response still carries.
%w[body output].each do |call|
  t.assert('output value to_s', "Nginx::Filter##{call == 'body' ? 'body=' : 'output'} with a value whose to_s does not return a String answers 500 with the body of the file when the script does not rescue") do
    filter_offset = File.size(output_value_to_s_log_path)
    status, line, _, body = output_value_to_s_get(output_value_to_s_path(call, 'to_s_not_string', false))
    log = File.open(output_value_to_s_log_path) do |f|
      f.seek(filter_offset)
      f.read.to_s
    end
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
    t.assert_equal "static file\n", body
    t.assert_include log, '#<TypeError: Integer cannot be converted to String>'
  end
end

# The worker that got the values above still answers.
t.assert('output value to_s', 'the server answers after the values that could not be converted') do
  status, line, _, body = output_value_to_s_get(output_value_to_s_path('rputs', 'string'))
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'http://example.com/string|returned', body
end

t.report
