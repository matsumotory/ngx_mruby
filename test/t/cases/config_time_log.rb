# Messages that ngx_mruby logs while nginx reads the configuration (issue
# #320): the compile info of each directive with code (http and stream, file
# and inline), the target variable of mruby_set and mruby_set_code, and
# "mechanism enabled". nginx reads the configuration through its startup log,
# whose level is notice whatever error_log says, and uses the configured
# error_log only after that, so error_log cannot filter these messages. They
# are logged at info: a normal start drops them, and nginx -t, which raises
# the startup log to info, prints them.
# Config: test/conf/conf.d/63-config-time-log.conf (port 18140).
# Hook: test/html/config_time_log.rb. nginx_t and html_path are in
# test/t/cases/_prelude.rb.

t = SimpleTest.new "ngx_mruby test: configuration-time log messages"

CONFIG_TIME_LOG_PORT = 18140

# The kind of configuration-time message in one line of an error log, or nil.
# The code of an inline directive is logged with its line breaks, so only the
# first line of such a message has the level and the text matched here.
def config_time_message(line)
  if line.include?(') mechanism enabled in ')
    'mechanism enabled'
  elsif line.include?(': target variable=(')
    'set target variable'
  elsif line.include?(': compile info: code->code.file=(')
    line.include?('ngx_stream_mruby_') ? 'stream file' : 'http file'
  elsif line.include?(': compile info: code->code.string=(')
    line.include?('ngx_stream_mruby_') ? 'stream inline' : 'http inline'
  end
end

# The kinds of configuration-time messages logged at the given level.
def config_time_messages(log, level)
  log.split("\n").select { |l| l.include?("[#{level}] ") }.map { |l| config_time_message(l) }.compact.uniq.sort
end

# test.sh empties error.log before it starts nginx, and the configuration of
# that nginx has every kind of message above (nginx.conf, nginx.stream.conf
# and the fragments). The startup log and error_log are the same file there.
t.assert('config-time log - the started nginx logged no configuration-time message at notice', 'logs/error.log') do
  log = File.read(File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log'))
  t.assert_equal [], config_time_messages(log, 'notice')
  # error_log is at debug, but the startup log drops info.
  t.assert_equal [], config_time_messages(log, 'info')
end

t.assert('config-time log - the handlers of the fragment answer', 'locations /config_time_log/* on 18140') do
  res = HttpRequest.new.get base(CONFIG_TIME_LOG_PORT) + '/config_time_log/file'
  t.assert_equal 200, res.code
  t.assert_equal 'file handler ran, set code ran', res["body"]
  res = HttpRequest.new.get base(CONFIG_TIME_LOG_PORT) + '/config_time_log/inline'
  t.assert_equal 200, res.code
  t.assert_equal 'inline handler ran', res["body"]
end

# nginx_t writes the startup log to logs/nginx_t.log, which test.sh keeps
# between runs, so only the part that this nginx -t appended is read. The
# stream server follows the one on port 12345 of test/conf/nginx.stream.conf:
# the file version replaces the inline code as the handler. nginx -t
# compiles both and runs neither.
t.assert('config-time log - nginx -t logs the configuration-time messages at info', 'nginx -t') do
  dir = ENV['NGINX_INSTALL_DIR']
  log_path = File.join(dir, 'logs', 'nginx_t.log')
  before = File.exist?(log_path) ? File.read(log_path).bytesize : 0
  out = nginx_t([
    'http {',
    "    include #{File.join(dir, 'conf', 'conf.d', '63-config-time-log.conf')};",
    '}',
    'stream {',
    '    upstream dynamic_server1 {',
    '        server 127.0.0.1:18080;',
    '    }',
    '    server {',
    "        listen 127.0.0.1:#{CONFIG_TIME_LOG_PORT};",
    %q{        mruby_stream_code 'raise "a replaced stream handler ran"';},
    "        mruby_stream #{html_path('stream_lb.rb')};",
    '        proxy_pass dynamic_server1;',
    '    }',
    '}',
  ].join("\n"))
  log = File.read(log_path)
  log = log.byteslice(before, log.bytesize - before)
  t.assert_include out, 'test is successful'
  t.assert_equal ['http file', 'http inline', 'mechanism enabled', 'set target variable', 'stream file', 'stream inline'],
                 config_time_messages(log, 'info')
  t.assert_equal [], config_time_messages(log, 'notice')
end

t.report
