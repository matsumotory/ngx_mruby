# The line of error.log for an exception whose class redefines #inspect or
# #backtrace so that they raise. ngx_mruby writes the class of the exception
# in place of its inspect, and the worker goes on to answer the next request
# or session: when the handler runs directly under nginx, and when it runs
# inside another mruby call (the target of Nginx.redirect from an mruby_set
# handler), where the exception of #inspect or #backtrace must stop in the
# logging, as an exception of the resumed fiber stops in
# ngx_mrb_fiber_resume; when it went on to the outer call, nginx did not
# finish the request, and the client waited for the response.
# Config: test/conf/conf.d/93-exception-log-raising-methods.conf (port 18198)
# and test/conf/conf.d/stream/51-exception-log-raising-methods.conf (port
# 12382).

t = SimpleTest.new "ngx_mruby test: the line of an exception whose inspect or backtrace raises"

def raising_methods_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

# The lines that error.log gets from offset on.
def raising_methods_lines_from(offset)
  File.open(raising_methods_log_path) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
end

# What a line says after the time, the level, the process and thread ids
# and the number of the connection.
def raising_methods_message(line)
  rest = line.split('] ', 2)[1].to_s.split(': ', 2)[1].to_s
  rest.start_with?('*') ? rest.split(' ', 2)[1].to_s : rest
end

# The lines at the error level. In the debug build of test.sh, the frames of
# a backtrace that is not redefined are lines at the error level as well.
def raising_methods_errors(lines)
  lines.select { |l| l.include?(' [error] ') }
end

# The lines of an exception (not those of its frames).
def raising_methods_exception_lines(lines)
  raising_methods_errors(lines).select { |l| l.include?('mrb_run failed') }
end

t.assert('exception log', 'an exception whose inspect raises: the line names its class, and the worker answers the next request') do
  offset = File.size(raising_methods_log_path)
  res = HttpRequest.new.get base(18198) + '/exception_log/inspect_raises'
  lines = raising_methods_lines_from(offset)
  errors = raising_methods_exception_lines(lines)
  t.assert_equal 500, res["code"]
  t.assert_equal 1, errors.size
  # the exception of the inspect is not logged
  t.assert_equal [], lines.select { |l| l.include?('exception log: inspect raised 42') }
  t.assert_true raising_methods_message(errors[0].to_s).start_with?(
    'mrb_run failed: return 500 HTTP status code to client: error: ' \
    '#<ExceptionLogInspectRaises> (inspect raised ArgumentError), client: 127.0.0.1, server: localhost, ' \
    'request: "GET /exception_log/inspect_raises HTTP/1.'
  ), errors[0].to_s
  t.assert_equal 'hello', HttpRequest.new.get(base(18198) + '/exception_log/hello')["body"]
end

t.assert('exception log', 'an exception whose backtrace raises: the line of the exception, a line at the debug level and no frame') do
  offset = File.size(raising_methods_log_path)
  res = HttpRequest.new.get base(18198) + '/exception_log/backtrace_raises'
  lines = raising_methods_lines_from(offset)
  errors = raising_methods_errors(lines)
  t.assert_equal 500, res["code"]
  t.assert_equal 1, errors.size
  t.assert_true raising_methods_message(errors[0].to_s).start_with?(
    'mrb_run failed: return 500 HTTP status code to client: error: ' \
    '#<ExceptionLogBacktraceRaises: exception log: backtrace raises 42>, client: 127.0.0.1'
  ), errors[0].to_s
  t.assert_equal 1, lines.select { |l| l.include?(' [debug] ') && l.include?('backtrace must be Array. mrb_type=') }.size
  t.assert_equal 'hello', HttpRequest.new.get(base(18198) + '/exception_log/hello')["body"]
end

t.assert('exception log', 'a stream session whose exception has an inspect that raises: the line names its class, for each session') do
  offset = File.size(raising_methods_log_path)
  tcp_client(12382)
  tcp_client(12382)
  lines = raising_methods_lines_from(offset)
  errors = raising_methods_exception_lines(lines)
  t.assert_equal 2, errors.size
  t.assert_equal [], lines.select { |l| l.include?('exception log: stream inspect raised 42') }
  errors.each do |l|
    t.assert_equal 'mrb_run failed: return NGX_ABORT to client: error: ' \
                   '#<ExceptionLogStreamInspectRaises> (inspect raised ArgumentError) ' \
                   'while initializing session, client: 127.0.0.1, server: 127.0.0.1:12382',
                   raising_methods_message(l)
  end
end


# Active connections of the nginx worker (stub_status counts all of them),
# without the one of this request. Connections that earlier tests kept alive
# may close between two calls, so the cases check that the count did not
# grow, as test/t/cases/redirect_to_raising_handler.rb does.
def raising_methods_active
  res = HttpRequest.new.get base(18198) + '/status'
  res["body"].split("\n")[0].split(":")[1].strip.to_i - 1
end

# Inside another mruby call: the content handler of the target of
# Nginx.redirect from an mruby_set handler raises. The client gets the 500 of
# that exception, nginx closes the connection, and the line of the exception
# is the one of the original exception.
t.assert('exception log', 'inside another mruby call, an exception whose inspect raises: the line names its class, and the worker answers the next request') do
  before = raising_methods_active
  offset = File.size(raising_methods_log_path)
  status, raw = tcp_client(18198, "GET /exception_log/set_redirect_inspect_raises HTTP/1.0\r\nHost: localhost\r\n\r\n")
  lines = raising_methods_lines_from(offset)
  errors = raising_methods_exception_lines(lines)
  after = raising_methods_active
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', raw.split("\r\n", 2)[0].to_s
  t.assert_true after <= before, "active connections grew from #{before} to #{after}"
  t.assert_equal 1, errors.size
  t.assert_equal [], lines.select { |l| l.include?('exception log: inspect raised 42') }
  t.assert_true raising_methods_message(errors[0].to_s).start_with?(
    'mrb_run failed: return 500 HTTP status code to client: error: ' \
    '#<ExceptionLogInspectRaises> (inspect raised ArgumentError), client: 127.0.0.1'
  ), errors[0].to_s
  t.assert_equal 'hello', HttpRequest.new.get(base(18198) + '/exception_log/hello')["body"]
end

t.assert('exception log', 'inside another mruby call, an exception whose backtrace raises: the line of the exception and a line at the debug level') do
  before = raising_methods_active
  offset = File.size(raising_methods_log_path)
  status, raw = tcp_client(18198, "GET /exception_log/set_redirect_backtrace_raises HTTP/1.0\r\nHost: localhost\r\n\r\n")
  lines = raising_methods_lines_from(offset)
  errors = raising_methods_exception_lines(lines)
  after = raising_methods_active
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 500 Internal Server Error', raw.split("\r\n", 2)[0].to_s
  t.assert_true after <= before, "active connections grew from #{before} to #{after}"
  t.assert_equal 1, errors.size
  t.assert_equal [], lines.select { |l| l.include?('exception log: backtrace raised 42') }
  t.assert_true raising_methods_message(errors[0].to_s).start_with?(
    'mrb_run failed: return 500 HTTP status code to client: error: ' \
    '#<ExceptionLogBacktraceRaises: exception log: backtrace raises 42>, client: 127.0.0.1'
  ), errors[0].to_s
  t.assert_equal 1, lines.select { |l| l.include?(' [debug] ') && l.include?('backtrace must be Array. mrb_type=') }.size
  t.assert_equal 'hello', HttpRequest.new.get(base(18198) + '/exception_log/hello')["body"]
end

t.report
