# The lines that ngx_mruby writes to error.log when Ruby code raises: their
# level and their text, for the code of a request, of an SSL handshake, of a
# stream session, and of the code that runs while nginx reads the
# configuration (mruby_init_code, mruby_stream_server_context_code). The
# lines of mruby_exit_worker_code and mruby_stream_exit_worker_code are in
# test/t/cases/config_hooks.rb, whose nginx runs those hooks.
# Config: test/conf/conf.d/91-exception-log.conf (ports 18192 and 18193) and
# test/conf/conf.d/stream/49-exception-log.conf (port 12380).

t = SimpleTest.new "ngx_mruby test: the lines of error.log for an exception"

def exception_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

# The lines that error.log gets from offset on.
def exception_log_lines_from(offset)
  File.open(exception_log_path) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
end

# What a line of error.log says after its time, its level, the process and
# thread ids and, for a connection, the number of the connection: the text
# that ngx_mruby wrote, followed by the context that nginx adds for a
# request or a connection. nil when the line does not have that form.
def exception_log_message(line)
  rest = line.split('] ', 2)[1]
  return nil unless rest
  rest = rest.split(': ', 2)[1]
  return nil unless rest
  rest = rest.split(' ', 2)[1].to_s if rest.start_with?('*')
  rest
end

# The lines of lines that contain marker and are not lines of a backtrace.
def exception_log_find(lines, marker)
  lines.select { |l| l.include?(marker) && l.include?('mrb_run failed') }
end

t.assert('exception log', 'an exception of a request handler: one line at the error level, with the request') do
  offset = File.size(exception_log_path)
  res = HttpRequest.new.get base(18192) + '/exception_log/request'
  found = exception_log_find(exception_log_lines_from(offset), 'exception log: http request 42')
  t.assert_equal 500, res["code"]
  t.assert_equal 1, found.size
  t.assert_include found[0].to_s, ' [error] '
  t.assert_true exception_log_message(found[0].to_s).to_s.start_with?(
    'mrb_run failed: return 500 HTTP status code to client: error: ' \
    '#<RuntimeError: exception log: http request 42>, client: 127.0.0.1, server: localhost, ' \
    'request: "GET /exception_log/request HTTP/1.'
  ), found[0].to_s
end

t.assert('exception log', 'an exception of an SSL handshake handler: one line at the error level, with the connection') do
  offset = File.size(exception_log_path)
  `openssl s_client -connect 127.0.0.1:18193 -servername localhost < /dev/null > /dev/null 2>&1`
  found = exception_log_find(exception_log_lines_from(offset), 'exception log: ssl handshake 42')
  t.assert_equal 1, found.size
  t.assert_include found[0].to_s, ' [error] '
  t.assert_true exception_log_message(found[0].to_s).to_s.start_with?(
    'ngx_mruby : mrb_run failed: return 500 HTTP status code to client: error: ' \
    '#<RuntimeError: exception log: ssl handshake 42>, client: 127.0.0.1, server: '
  ), found[0].to_s
end

t.assert('exception log', 'an exception of a stream session: one line at the error level, with the session') do
  offset = File.size(exception_log_path)
  _status, body = tcp_client(12380)
  found = exception_log_find(exception_log_lines_from(offset), 'exception log: stream session 42')
  t.assert_equal '', body
  t.assert_equal 1, found.size
  t.assert_include found[0].to_s, ' [error] '
  t.assert_true exception_log_message(found[0].to_s).to_s.start_with?(
    'mrb_run failed: return NGX_ABORT to client: error: ' \
    '#<RuntimeError: exception log: stream session 42>, client: 127.0.0.1, server: 127.0.0.1:12380'
  ), found[0].to_s
end

# nginx -t writes the lines at warn and above that it logs while it reads
# the configuration to its standard error as well, with "nginx: " before
# the level, and ngx_conf_log_error adds the file and the line of the
# configuration.
t.assert('exception log', 'nginx -t: an exception of mruby_init_code is a line at the error level with the file of the configuration') do
  out = nginx_t("http {\n    mruby_init_code 'raise \"exception log: http init \#{6 * 7}\"';\n}")
  conf = File.join(ENV['NGINX_INSTALL_DIR'], 'conf', 'nginx_t.conf')
  found = out.split("\n").select { |l| l.include?('exception log: http init 42') && l.include?('mrb_run failed') }
  t.assert_equal 1, found.size
  t.assert_true found[0].to_s.start_with?(
    "nginx: [error] mrb_run failed. error: #<RuntimeError: exception log: http init 42> in #{conf}:"
  ), found[0].to_s
  t.assert_include out, 'test failed'
end

t.assert('exception log', 'nginx -t: an exception of mruby_stream_server_context_code is a line at the emerg level with the file and line of the directive') do
  out = nginx_t("stream {\n    server {\n        listen 127.0.0.1:12380;\n" \
                "        mruby_stream_server_context_code 'raise \"exception log: stream server context \#{6 * 7}\"';\n" \
                "    }\n}")
  conf = File.join(ENV['NGINX_INSTALL_DIR'], 'conf', 'nginx_t.conf')
  line = File.read(conf).split("\n").index { |l| l.include?('mruby_stream_server_context_code') }.to_i + 1
  found = out.split("\n").select { |l| l.include?('exception log: stream server context 42') && l.include?('mrb_run failed') }
  t.assert_equal 1, found.size
  t.assert_equal "nginx: [emerg] mrb_run failed: ngx_mruby stream module configuration failed: error: " \
                 "#<RuntimeError: exception log: stream server context 42> in #{conf}:#{line}", found[0].to_s
  t.assert_include out, 'test failed'
end

t.report
