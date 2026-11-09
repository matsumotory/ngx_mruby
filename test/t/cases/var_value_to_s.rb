# The value of an mruby_set handler and of Nginx::Var when it is not a
# String. Config: test/conf/conf.d/83-var-value-to-s.conf (port 18159).
# Hook scripts: test/html/var_value_to_s_set.rb (the mruby_set handler) and
# test/html/var_value_to_s_var.rb (the content handler of /var/).
#
# ngx_mruby converts such a value with to_s. A value whose to_s is missing,
# raises or does not return a String cannot be converted:
#
# - In Ruby code, the setter of Nginx::Var and Nginx::Var#set raise: the
#   exception of to_s, or a TypeError when to_s does not return a String.
#   The variable keeps its value.
# - The value that an mruby_set handler returns counts as an exception of
#   the handler: before Nginx::Async.sleep, the variable is an empty string
#   and the request goes on; after the sleep, the request gets 500.
#
# Before the fix, these values could end the nginx process (test.sh runs a
# single process), so the cases after the first such value got no answer,
# or leave the exception of to_s in the mrb_state of the worker, where the
# next mruby handler found it and failed. The cases that convert
# successfully come first.

t = SimpleTest.new "ngx_mruby test: the value of mruby_set and Nginx::Var as a String"

def var_value_to_s_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

# Returns the status of the connection, the status line and the body.
def var_value_to_s_get(path)
  status, raw = tcp_client(18159, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
  head, body = raw.split("\r\n\r\n", 2)
  [status, head.to_s.split("\r\n")[0].to_s, body.to_s]
end

# Only without a wait: after Nginx::Async.sleep, an mruby_set handler that
# ends normally in this location ends the request without a response, as
# before this change, so the cases after the sleep below check only the
# values that cannot be converted.
[
  ['string', '["set"]'],
  ['integer', '["1"]'],
].each do |value, expected|
  t.assert('var value to_s', "an mruby_set handler that returns a #{value} sets the variable to it as a String") do
    status, line, body = var_value_to_s_get("/set/nowait/#{value}")
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal expected, body
  end
end

%w[setter set].each do |call|
  t.assert('var value to_s', "Nginx::Var (#{call}) with a String sets the variable") do
    status, line, body = var_value_to_s_get("/var/#{call}/string")
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal "returned: \"changed\"\nvar_value_to_s: \"changed\"", body
  end
end

# Ruby code: the call raises and the variable keeps "initial".
%w[setter set set_name].each do |call|
  [
    ['no_to_s', 'without to_s', 'raised: NoMethodError: ', 'to_s'],
    ['to_s_raises', 'whose to_s raises', 'raised: RuntimeError: ', 'raised in to_s'],
    ['to_s_not_string', 'whose to_s does not return a String', 'raised: TypeError: ', 'cannot be converted to String'],
  ].each do |value, what, raised, message|
    t.assert('var value to_s', "Nginx::Var (#{call}) with a value #{what} raises and leaves the variable unchanged") do
      status, line, body = var_value_to_s_get("/var/#{call}/#{value}")
      first, second = body.split("\n", 2)
      t.assert_equal 'EOF', status
      t.assert_equal 'HTTP/1.1 200 OK', line
      t.assert_true first.to_s.start_with?(raised), "the call raised: #{first}"
      t.assert_include first.to_s, message
      t.assert_equal 'var_value_to_s: "initial"', second
    end
  end
end

# An mruby_set handler whose value cannot be converted, or whose call of
# Nginx::Var raises: before a wait, the variable is an empty string and the
# request goes on; after Nginx::Async.sleep, the request gets 500.
offset = File.size(var_value_to_s_log_path)
[
  ['no_to_s', 'returns a value without to_s'],
  ['to_s_raises', 'returns a value whose to_s raises'],
  ['to_s_not_string', 'returns a value whose to_s does not return a String'],
  ['setter_not_string', 'calls the setter of Nginx::Var with a value whose to_s does not return a String'],
  ['set_not_string', 'calls Nginx::Var#set with a value whose to_s does not return a String'],
].each do |value, what|
  t.assert('var value to_s', "an mruby_set handler that #{what} sets the variable to an empty string") do
    status, line, body = var_value_to_s_get("/set/nowait/#{value}")
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal '[""]', body
  end

  t.assert('var value to_s', "an mruby_set handler that #{what} after Nginx::Async.sleep answers 500") do
    status, line, body = var_value_to_s_get("/set/sleep/#{value}")
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 500 Internal Server Error', line
    t.assert_include body, '<title>500 Internal Server Error</title>'
  end
end

t.assert('var value to_s', 'error.log has the exceptions of the values that an mruby_set handler could not convert') do
  log = File.open(var_value_to_s_log_path) do |f|
    f.seek(offset)
    f.read.to_s
  end
  t.assert_include log, "undefined method 'to_s'"
  t.assert_include log, 'raised in to_s'
  t.assert_include log, 'cannot be converted to String'
end

# The worker that converted the values above still answers.
t.assert('var value to_s', 'the server answers after the values that could not be converted') do
  status, line, body = var_value_to_s_get('/set/nowait/string')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal '["set"]', body
end

t.report
