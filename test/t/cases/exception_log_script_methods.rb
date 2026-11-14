# The lines of error.log for an exception whose class redefines #inspect or
# #backtrace, which ngx_mruby calls when it writes the exception to
# error.log: they raise, or return values other than a String and an Array
# of Strings. The line names the class of the exception in place of an
# inspect that raised or did not return a String, the Strings of the
# backtrace are logged and its other elements skipped, and the worker goes
# on to answer the next request or session: when the handler runs directly
# under nginx, and when it runs inside another mruby call (the target of
# Nginx.redirect from an mruby_set handler). There, an exception of #inspect
# or #backtrace that went on to the outer call left nginx without finishing
# the request, and the client waited for the response.
# Config: test/conf/conf.d/94-exception-log-script-methods.conf (port 18091)
# and test/conf/conf.d/stream/52-exception-log-script-methods.conf (ports
# 12389 and 12383).

t = SimpleTest.new "ngx_mruby test: the line of an exception whose inspect or backtrace is redefined"

# The classes of the exceptions whose #inspect is not redefined. The runner
# of the cases is built from the same mruby/ tree as nginx, so the inspect
# of an exception here is the text that nginx writes for it.
class ScriptMethodsBacktraceRaises < RuntimeError; end
class ScriptMethodsBacktraceTypes < RuntimeError; end
class ScriptMethodsBacktraceNotArray < RuntimeError; end

def script_methods_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

# The lines that error.log gets from offset on.
def script_methods_lines_from(offset)
  File.open(script_methods_log_path) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
end

# What a line says after the time, the level, the process and thread ids
# and the number of the connection.
def script_methods_message(line)
  rest = line.split('] ', 2)[1].to_s.split(': ', 2)[1].to_s
  rest.start_with?('*') ? rest.split(' ', 2)[1].to_s : rest
end

# The lines at the error level. In the debug build of test.sh, the frames of
# a backtrace are lines at the error level as well.
def script_methods_errors(lines)
  lines.select { |l| l.include?(' [error] ') }
end

# The lines of an exception (not those of its frames).
def script_methods_exception_lines(lines)
  script_methods_errors(lines).select { |l| l.include?('mrb_run failed') }
end

# Active connections of the nginx worker (stub_status counts all of them),
# without the one of this request. Connections that earlier tests kept alive
# may close between two calls, so the cases check that the count did not
# grow, as test/t/cases/redirect_to_raising_handler.rb does.
def script_methods_active
  res = HttpRequest.new.get base(18091) + '/status'
  res["body"].split("\n")[0].split(":")[1].strip.to_i - 1
end

PREFIX_500 = 'mrb_run failed: return 500 HTTP status code to client: error: '

t.assert('exception log', 'an exception whose inspect raises: the line names its class, and the worker answers the next request') do
  offset = File.size(script_methods_log_path)
  res = HttpRequest.new.get base(18091) + '/script_methods/inspect_raises'
  lines = script_methods_lines_from(offset)
  errors = script_methods_exception_lines(lines)
  t.assert_equal 500, res["code"]
  t.assert_equal 1, errors.size
  # the exception of the inspect is not logged
  t.assert_equal [], lines.select { |l| l.include?('script methods: inspect raised 42') }
  t.assert_true script_methods_message(errors[0].to_s).start_with?(
    PREFIX_500 + '#<ScriptMethodsInspectRaises> (inspect raised ArgumentError), client: 127.0.0.1, server: localhost, ' \
    'request: "GET /script_methods/inspect_raises HTTP/1.'
  ), errors[0].to_s
  t.assert_equal 'hello', HttpRequest.new.get(base(18091) + '/script_methods/hello')["body"]
end

t.assert('exception log', 'an exception whose backtrace raises: the line of the exception, a line at the debug level and no frame') do
  offset = File.size(script_methods_log_path)
  res = HttpRequest.new.get base(18091) + '/script_methods/backtrace_raises'
  lines = script_methods_lines_from(offset)
  errors = script_methods_errors(lines)
  t.assert_equal 500, res["code"]
  t.assert_equal 1, errors.size
  t.assert_true script_methods_message(errors[0].to_s).start_with?(
    PREFIX_500 + ScriptMethodsBacktraceRaises.new('script methods: backtrace raises 42').inspect + ', client: 127.0.0.1'
  ), errors[0].to_s
  t.assert_equal 1, lines.select { |l| l.include?(' [debug] ') && l.include?('backtrace must be Array. mrb_type=') }.size
  t.assert_equal 'hello', HttpRequest.new.get(base(18091) + '/script_methods/hello')["body"]
end

t.assert('exception log', 'an exception whose inspect does not return a String: the line names its class, and the worker answers the next request') do
  offset = File.size(script_methods_log_path)
  res = HttpRequest.new.get base(18091) + '/script_methods/inspect_not_string'
  errors = script_methods_exception_lines(script_methods_lines_from(offset))
  t.assert_equal 500, res["code"]
  t.assert_equal 1, errors.size
  t.assert_true script_methods_message(errors[0].to_s).start_with?(
    PREFIX_500 + '#<ScriptMethodsInspectNotString> (inspect did not return a String), client: 127.0.0.1, server: localhost, ' \
    'request: "GET /script_methods/inspect_not_string HTTP/1.'
  ), errors[0].to_s
  t.assert_equal 'hello', HttpRequest.new.get(base(18091) + '/script_methods/hello')["body"]
end

t.assert('exception log', 'an exception whose inspect returns a String: the line has that String') do
  offset = File.size(script_methods_log_path)
  res = HttpRequest.new.get base(18091) + '/script_methods/inspect_string'
  errors = script_methods_exception_lines(script_methods_lines_from(offset))
  t.assert_equal 500, res["code"]
  t.assert_equal 1, errors.size
  t.assert_true script_methods_message(errors[0].to_s).start_with?(
    PREFIX_500 + 'script methods: the inspect of the script 42, client: 127.0.0.1, server: localhost, ' \
    'request: "GET /script_methods/inspect_string HTTP/1.'
  ), errors[0].to_s
end

t.assert('exception log', 'a redefined backtrace with elements that are not Strings: its Strings are logged, the rest is skipped') do
  offset = File.size(script_methods_log_path)
  res = HttpRequest.new.get base(18091) + '/script_methods/backtrace_types'
  lines = script_methods_lines_from(offset)
  found = script_methods_exception_lines(lines)
  frames = script_methods_errors(lines).reject { |l| l.include?('mrb_run failed') }
  t.assert_equal 500, res["code"]
  t.assert_equal 1, found.size
  t.assert_true script_methods_message(found[0].to_s).start_with?(
    PREFIX_500 + ScriptMethodsBacktraceTypes.new('script methods: backtrace types 42').inspect + ', client: 127.0.0.1'
  ), found[0].to_s
  t.assert_equal 2, frames.size
  t.assert_true script_methods_message(frames[0].to_s).start_with?('script methods: first frame 42, client: 127.0.0.1'), frames[0].to_s
  t.assert_true script_methods_message(frames[1].to_s).start_with?('script methods: last frame 42, client: 127.0.0.1'), frames[1].to_s
  t.assert_equal 'hello', HttpRequest.new.get(base(18091) + '/script_methods/hello')["body"]
end

t.assert('exception log', 'a redefined backtrace that returns nil: a line at the debug level, and no frame') do
  offset = File.size(script_methods_log_path)
  res = HttpRequest.new.get base(18091) + '/script_methods/backtrace_not_array'
  lines = script_methods_lines_from(offset)
  found = script_methods_exception_lines(lines)
  not_array = lines.select { |l| l.include?('backtrace must be Array. mrb_type=') }
  t.assert_equal 500, res["code"]
  t.assert_equal 1, found.size
  t.assert_true script_methods_message(found[0].to_s).start_with?(
    PREFIX_500 + ScriptMethodsBacktraceNotArray.new('script methods: backtrace not array 42').inspect + ', client: 127.0.0.1'
  ), found[0].to_s
  t.assert_equal 1, not_array.size
  t.assert_include not_array[0].to_s, ' [debug] '
  t.assert_equal [found[0]], script_methods_errors(lines)
  t.assert_equal 'hello', HttpRequest.new.get(base(18091) + '/script_methods/hello')["body"]
end

# Inside another mruby call: the content handler of the target of
# Nginx.redirect from an mruby_set handler raises. The client gets the 500 of
# that exception, nginx closes the connection, and the line of the exception
# is the one of the original exception.
t.assert('exception log', 'inside another mruby call, an exception whose inspect raises: the line names its class, and the worker answers the next request') do
  before = script_methods_active
  offset = File.size(script_methods_log_path)
  status, raw = tcp_client(18091, "GET /script_methods/set_redirect_inspect_raises HTTP/1.0\r\nHost: localhost\r\n\r\n")
  lines = script_methods_lines_from(offset)
  errors = script_methods_exception_lines(lines)
  after = script_methods_active
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', raw.split("\r\n", 2)[0].to_s
  t.assert_true after <= before, "active connections grew from #{before} to #{after}"
  t.assert_equal 1, errors.size
  t.assert_equal [], lines.select { |l| l.include?('script methods: inspect raised 42') }
  t.assert_true script_methods_message(errors[0].to_s).start_with?(
    PREFIX_500 + '#<ScriptMethodsInspectRaises> (inspect raised ArgumentError), client: 127.0.0.1'
  ), errors[0].to_s
  t.assert_equal 'hello', HttpRequest.new.get(base(18091) + '/script_methods/hello')["body"]
end

t.assert('exception log', 'inside another mruby call, an exception whose backtrace raises: the line of the exception and a line at the debug level') do
  before = script_methods_active
  offset = File.size(script_methods_log_path)
  status, raw = tcp_client(18091, "GET /script_methods/set_redirect_backtrace_raises HTTP/1.0\r\nHost: localhost\r\n\r\n")
  lines = script_methods_lines_from(offset)
  errors = script_methods_exception_lines(lines)
  after = script_methods_active
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', raw.split("\r\n", 2)[0].to_s
  t.assert_true after <= before, "active connections grew from #{before} to #{after}"
  t.assert_equal 1, errors.size
  t.assert_equal [], lines.select { |l| l.include?('script methods: backtrace raised 42') }
  t.assert_true script_methods_message(errors[0].to_s).start_with?(
    PREFIX_500 + ScriptMethodsBacktraceRaises.new('script methods: backtrace raises 42').inspect + ', client: 127.0.0.1'
  ), errors[0].to_s
  t.assert_equal 1, lines.select { |l| l.include?(' [debug] ') && l.include?('backtrace must be Array. mrb_type=') }.size
  t.assert_equal 'hello', HttpRequest.new.get(base(18091) + '/script_methods/hello')["body"]
end

# The same path with an #inspect or a #backtrace that does not raise. Before
# the fix, these left the request unfinished as well: the method ran while
# the exception was still pending, and so returned it by a jump to the
# outer call.
t.assert('exception log', 'inside another mruby call, an exception whose inspect returns a String: the line has that String, and the worker answers the next request') do
  before = script_methods_active
  offset = File.size(script_methods_log_path)
  status, raw = tcp_client(18091, "GET /script_methods/set_redirect_inspect_string HTTP/1.0\r\nHost: localhost\r\n\r\n")
  errors = script_methods_exception_lines(script_methods_lines_from(offset))
  after = script_methods_active
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', raw.split("\r\n", 2)[0].to_s
  t.assert_true after <= before, "active connections grew from #{before} to #{after}"
  t.assert_equal 1, errors.size
  t.assert_true script_methods_message(errors[0].to_s).start_with?(
    PREFIX_500 + 'script methods: the inspect of the script 42, client: 127.0.0.1'
  ), errors[0].to_s
  t.assert_equal 'hello', HttpRequest.new.get(base(18091) + '/script_methods/hello')["body"]
end

t.assert('exception log', 'inside another mruby call, a redefined backtrace that returns an Array: its Strings are logged, and the worker answers the next request') do
  before = script_methods_active
  offset = File.size(script_methods_log_path)
  status, raw = tcp_client(18091, "GET /script_methods/set_redirect_backtrace_types HTTP/1.0\r\nHost: localhost\r\n\r\n")
  lines = script_methods_lines_from(offset)
  errors = script_methods_exception_lines(lines)
  frames = script_methods_errors(lines).reject { |l| l.include?('mrb_run failed') }
  after = script_methods_active
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', raw.split("\r\n", 2)[0].to_s
  t.assert_true after <= before, "active connections grew from #{before} to #{after}"
  t.assert_equal 1, errors.size
  t.assert_true script_methods_message(errors[0].to_s).start_with?(
    PREFIX_500 + ScriptMethodsBacktraceTypes.new('script methods: backtrace types 42').inspect + ', client: 127.0.0.1'
  ), errors[0].to_s
  t.assert_equal 2, frames.size
  t.assert_true script_methods_message(frames[0].to_s).start_with?('script methods: first frame 42, client: 127.0.0.1'), frames[0].to_s
  t.assert_true script_methods_message(frames[1].to_s).start_with?('script methods: last frame 42, client: 127.0.0.1'), frames[1].to_s
  t.assert_equal 'hello', HttpRequest.new.get(base(18091) + '/script_methods/hello')["body"]
end

t.assert('exception log', 'a stream session whose exception has an inspect that raises: the line names its class, for each session') do
  offset = File.size(script_methods_log_path)
  tcp_client(12389)
  tcp_client(12389)
  lines = script_methods_lines_from(offset)
  errors = script_methods_exception_lines(lines)
  t.assert_equal 2, errors.size
  t.assert_equal [], lines.select { |l| l.include?('script methods: stream inspect raised 42') }
  errors.each do |l|
    t.assert_equal 'mrb_run failed: return NGX_ABORT to client: error: ' \
                   '#<ScriptMethodsStreamInspectRaises> (inspect raised ArgumentError) ' \
                   'while initializing session, client: 127.0.0.1, server: 127.0.0.1:12389',
                   script_methods_message(l)
  end
end

t.assert('exception log', 'a stream session whose exception has an inspect that does not return a String: the line names its class, for each session') do
  offset = File.size(script_methods_log_path)
  tcp_client(12383)
  tcp_client(12383)
  errors = script_methods_exception_lines(script_methods_lines_from(offset))
  t.assert_equal 2, errors.size
  errors.each do |l|
    t.assert_equal 'mrb_run failed: return NGX_ABORT to client: error: ' \
                   '#<ScriptMethodsStreamInspectNotString> (inspect did not return a String) ' \
                   'while initializing session, client: 127.0.0.1, server: 127.0.0.1:12383',
                   script_methods_message(l)
  end
end

t.report
