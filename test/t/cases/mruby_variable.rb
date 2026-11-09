# mruby_variable $name [value]; declares a variable in the http {} block that
# scripts assign with Nginx::Var.
# Config: test/conf/conf.d/89-mruby-variable.conf (port 18171).
#
# The server rewrite handler there assigns $mruby_variable_key, and the
# cases check that a content handler, nginx's return, add_header and
# access_log read the assigned value, that the variables read as their
# declared values without an assignment, and that "set" assigns them as
# well. The cases with nginx_t (test/t/cases/_prelude.rb) check the names
# that nginx -t refuses and accepts.
#
# A request is sent with HTTP/1.0, and tcp_client returns when nginx closed
# the connection. nginx runs the log phase before it closes the connection,
# so the line of the request is in the access log by then. The log format
# is "$request_uri [$mruby_variable_key] [$mruby_variable_default]".

t = SimpleTest.new "ngx_mruby test: mruby_variable"

MRUBY_VARIABLE_PORT = 18171

def mruby_variable_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'mruby_variable.log')
end

def mruby_variable_log_size
  File.exist?(mruby_variable_log_path) ? File.size(mruby_variable_log_path) : 0
end

# Sends GET path and returns the status of the connection, the status line,
# the response headers (names in lowercase), the body and the access log
# lines of the request.
def mruby_variable_get(path)
  offset = mruby_variable_log_size
  status, raw = tcp_client(MRUBY_VARIABLE_PORT, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
  head, body = raw.split("\r\n\r\n", 2)
  lines = head.to_s.split("\r\n")
  headers = {}
  lines[1..-1].to_a.each do |line|
    name, value = line.split(':', 2)
    headers[name.downcase] = value.to_s.strip
  end
  log = File.open(mruby_variable_log_path) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
  [status, lines[0].to_s, headers, body.to_s, log]
end

[
  ['/assigned', 'a content handler'],
  ['/assigned_return', "nginx's return"],
].each do |path, reader|
  t.assert('mruby_variable', "#{reader}, add_header and access_log read the value that a server rewrite handler assigned") do
    status, line, headers, body, log = mruby_variable_get(path)
    t.assert_equal 'EOF', status
    t.assert_equal 'HTTP/1.1 200 OK', line
    t.assert_equal '[from-ruby] [default-GET]', body
    t.assert_equal '[from-ruby]', headers['x-mruby-variable-key']
    t.assert_equal '[default-GET]', headers['x-mruby-variable-default']
    t.assert_equal ["#{path} [from-ruby] [default-GET]"], log
  end
end

t.assert('mruby_variable', 'without an assignment, a variable reads as its declared value, or as the empty string without one') do
  status, line, headers, body, log = mruby_variable_get('/default')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal '[] [default-GET]', body
  t.assert_equal '[]', headers['x-mruby-variable-key']
  t.assert_equal '[default-GET]', headers['x-mruby-variable-default']
  t.assert_equal ['/default [] [default-GET]'], log
end

t.assert('mruby_variable', '"set" and a content handler assign the declared variables too') do
  status, line, headers, body, log = mruby_variable_get('/assigned_set')
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal '[from-set] [from-content]', body
  t.assert_equal '[from-set]', headers['x-mruby-variable-key']
  t.assert_equal '[from-content]', headers['x-mruby-variable-default']
  t.assert_equal ['/assigned_set [from-set] [from-content]'], log
end

# The reason for a variable that nginx does not let scripts change, and the
# one for a changeable variable with a get handler of another module or of
# a named capture of a regular expression, which nginx does not let a
# module tell apart.
OTHER_VALUE = 'another module defines it with a value of its own'
OTHER_OR_CAPTURE = 'another module defines it with a value of its own, or a named capture of a regular expression assigns it'

[
  ['$uri, which nginx does not let scripts change', 'mruby_variable $uri;',
   "[emerg] mruby_variable cannot declare \"$uri\": #{OTHER_VALUE} in "],
  ['$args, which scripts may change but which has a value of its own', 'mruby_variable $args;',
   "[emerg] mruby_variable cannot declare \"$args\": #{OTHER_OR_CAPTURE}"],
  ['$http_x_agent, a request header', 'mruby_variable $http_x_agent;',
   '[emerg] mruby_variable cannot declare "$http_x_agent": nginx gives the variables whose names begin with "http_" their values'],
  ['a variable of an earlier map', "map $request_method $mruby_variable_mapped { default mapped; }\n    mruby_variable $mruby_variable_mapped;",
   "[emerg] mruby_variable cannot declare \"$mruby_variable_mapped\": #{OTHER_OR_CAPTURE}"],
  ['a variable of a later map', "mruby_variable $mruby_variable_later;\n    map $request_method $mruby_variable_later { default mapped; }",
   "[emerg] mruby_variable cannot declare \"$mruby_variable_later\" in "],
  ['a named capture of an earlier location', "server {\n        location ~ ^/agents/(?<mruby_variable_capture>[^/]+) {\n        }\n    }\n    mruby_variable $mruby_variable_capture;",
   "[emerg] mruby_variable cannot declare \"$mruby_variable_capture\": #{OTHER_OR_CAPTURE}"],
  ['a named capture of a later location', "mruby_variable $mruby_variable_capture_later;\n    server {\n        location ~ ^/agents/(?<mruby_variable_capture_later>[^/]+) {\n        }\n    }",
   "[emerg] mruby_variable cannot declare \"$mruby_variable_capture_later\" in "],
  ['a second declaration of the same name', "mruby_variable $mruby_variable_twice;\n    mruby_variable $mruby_variable_twice;",
   '[emerg] mruby_variable "$mruby_variable_twice" is duplicate: it is declared in '],
  ['a name without "$"', 'mruby_variable mruby_variable_no_dollar;',
   '[emerg] invalid variable name "mruby_variable_no_dollar"'],
  ['the directive in a server block', "server {\n        mruby_variable $mruby_variable_in_server;\n    }",
   '[emerg] "mruby_variable" directive is not allowed here'],
].each do |what, directives, message|
  t.assert('mruby_variable', "nginx -t refuses #{what}") do
    out = nginx_t("http {\n    #{directives}\n}")
    t.assert_include out, message
    t.assert_include out, 'test failed'
    t.assert_not_include out, 'test is successful'
  end
end

t.assert('mruby_variable', 'nginx -t refuses a variable of a later map with the file and the line of the declaration') do
  out = nginx_t("http {\n    mruby_variable $mruby_variable_later;\n    map $request_method $mruby_variable_later { default mapped; }\n}")
  # the line of the directive in the file that nginx_t wrote, which starts
  # with a load_module line in a dynamic module build
  conf = File.join(ENV['NGINX_INSTALL_DIR'], 'conf', 'nginx_t.conf')
  lines = File.open(conf) { |f| f.read.to_s.split("\n") }
  line = lines.index { |l| l.include?('mruby_variable $mruby_variable_later;') } + 1
  t.assert_include out, "#{conf}:#{line}: #{OTHER_OR_CAPTURE}"
end

t.assert('mruby_variable', 'nginx -t refuses a named capture of a later location with the file and the line of the declaration') do
  out = nginx_t("http {\n    mruby_variable $mruby_variable_capture_later;\n    server {\n        location ~ ^/agents/(?<mruby_variable_capture_later>[^/]+) {\n        }\n    }\n}")
  conf = File.join(ENV['NGINX_INSTALL_DIR'], 'conf', 'nginx_t.conf')
  lines = File.open(conf) { |f| f.read.to_s.split("\n") }
  line = lines.index { |l| l.include?('mruby_variable $mruby_variable_capture_later;') } + 1
  t.assert_include out, "#{conf}:#{line}: #{OTHER_OR_CAPTURE}"
end

[
  ['a name that an earlier "set" assigns', "server {\n        location / {\n            set $mruby_variable_set_first \"\";\n        }\n    }\n    mruby_variable $mruby_variable_set_first;"],
  ['a name that a later "set" assigns', "mruby_variable $mruby_variable_set_later;\n    server {\n        location / {\n            set $mruby_variable_set_later \"\";\n        }\n    }"],
  ['a name that an earlier mruby_set_code assigns', "server {\n        location / {\n            mruby_set_code $mruby_variable_ndk_first '\"x\"';\n        }\n    }\n    mruby_variable $mruby_variable_ndk_first;"],
].each do |what, directives|
  t.assert('mruby_variable', "nginx -t accepts #{what}") do
    out = nginx_t("http {\n    #{directives}\n}")
    t.assert_include out, 'test is successful'
    t.assert_not_include out, '[emerg]'
  end
end

t.report
