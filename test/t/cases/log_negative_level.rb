# Nginx.log and Nginx::Stream.log with a negative level write one line at the
# error level instead of the message: the name of the module and of the C
# function of the method, then "log level is not positive number". The
# message itself is not written.
# Config: test/conf/conf.d/92-log-negative-level.conf (port 18194) and
# test/conf/conf.d/stream/50-log-negative-level.conf (port 12381).

t = SimpleTest.new "ngx_mruby test: Nginx.log with a negative level"

def log_negative_level_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

# The lines that error.log gets from offset on.
def log_negative_level_lines_from(offset)
  File.open(log_negative_level_path) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
end

# The lines of error.log from offset on that name the check of the level.
def log_negative_level_lines(offset)
  log_negative_level_lines_from(offset).select { |l| l.include?('log level is not positive number') }
end

# What a line says after the time, the level, the process and thread ids
# and the number of the connection.
def log_negative_level_message(line)
  rest = line.split('] ', 2)[1].to_s.split(': ', 2)[1].to_s
  rest.start_with?('*') ? rest.split(' ', 2)[1].to_s : rest
end

t.assert('Nginx.log', 'a negative level in a content handler writes the line of the module and of ngx_mrb_errlogger') do
  offset = File.size(log_negative_level_path)
  res = HttpRequest.new.get base(18194) + '/log_negative_level'
  found = log_negative_level_lines(offset)
  t.assert_equal 200, res["code"]
  t.assert_equal 'logged', res["body"]
  t.assert_equal 1, found.size
  t.assert_include found[0].to_s, ' [error] '
  t.assert_true log_negative_level_message(found[0].to_s).start_with?(
    'ngx_mruby ERROR ngx_mrb_errlogger: log level is not positive number, client: 127.0.0.1, server: localhost'
  ), found[0].to_s
  # the message itself is not written
  t.assert_equal [], log_negative_level_lines_from(offset).select { |l| l.include?(' log negative level: http, ') }
end

t.assert('Nginx::Stream.log', 'a negative level in a stream session writes the line of the module and of ngx_stream_mrb_errlogger') do
  offset = File.size(log_negative_level_path)
  tcp_client(12381)
  found = log_negative_level_lines(offset)
  t.assert_equal 1, found.size
  t.assert_include found[0].to_s, ' [error] '
  t.assert_equal 'ngx_mruby-stream-module ERROR ngx_stream_mrb_errlogger: log level is not positive number ' \
                 'while initializing session, client: 127.0.0.1, server: 127.0.0.1:12381',
                 log_negative_level_message(found[0].to_s)
end

t.report
