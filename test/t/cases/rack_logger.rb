# The methods of the logger in env["rack.logger"] (Kernel::Rack::Logger of
# mrbgems/rack-based-api).
# Config: test/conf/conf.d/71-rack-logger.conf (port 18157).

t = SimpleTest.new "ngx_mruby test: rack logger"

def rack_logger_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

def rack_logger_log_lines(offset)
  File.open(rack_logger_log_path) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
end

t.assert('Rack logger - each method writes one error.log line at its nginx level', 'GET /rack_logger/levels on 18157') do
  offset = File.size(rack_logger_log_path)
  res = HttpRequest.new.get base(18157) + '/rack_logger/levels'
  t.assert_equal 200, res.code
  t.assert_equal 'logged', res["body"]

  # A line of nginx's error log is "TIME [LEVEL] PID#TID: *CONN MESSAGE,
  # client: ...". nginx leaves out the part from ", client: " at the debug
  # level. The test build of mruby has no Regexp, so the line is cut at the
  # known separators.
  found = []
  rack_logger_log_lines(offset).each do |l|
    next unless l.include?('rack logger case ')
    message = l.split('rack logger case ', 2)[1].to_s
    name = message.split(' ')[0].to_s
    next unless message == "#{name} 42" || message.start_with?("#{name} 42, client: ")
    found << "#{name}:#{l.split('[', 2)[1].to_s.split(']')[0]}"
  end
  t.assert_equal ['fatal:emerg', 'error:error', 'warn:warn', 'info:info', 'debug:debug',
                  'emerg:emerg', 'alert:alert', 'crit:crit', 'notice:notice', 'block:info'], found
end

t.report
