# Directives that the running test nginx cannot show: mruby_output_filter
# and mruby_output_filter_code, which nginx rejects while it reads the
# configuration, and mruby_exit_worker_code and
# mruby_stream_exit_worker_code, which run when nginx stops. nginx_t is in
# test/t/cases/_prelude.rb.
#
# The exit hooks run in an nginx that this file starts on port 18158 and
# stops with "nginx -s quit", as the stream-only test at the end of
# test/t/ngx_mruby.rb does. It runs as a single process, as the test nginx
# does, so the hooks run in the process that nginx -s quit signals. Its
# prefix is NGINX_INSTALL_DIR/exit_hooks/. The hooks write with Nginx.log and
# Nginx::Stream.log, because nginx sends its standard output to /dev/null
# when it runs as a daemon.

t = SimpleTest.new "ngx_mruby test: configuration-time and exit hooks"

REMOVED_OUTPUT_FILTER_MESSAGE = 'mruby_output_filter{,_code} was deleted from v1.17.2, you should use ' \
  'mruby_output_body_filter{,_code} for response body, or use ' \
  'mruby_output_header_filter{,_code} for response headers.'

t.assert('config hooks - nginx -t rejects mruby_output_filter with the message of the removed directive', 'nginx -t') do
  out = nginx_t("http {\n    mruby_output_filter #{html_path('unified_hello.rb')};\n}")
  t.assert_include out, "[emerg] #{REMOVED_OUTPUT_FILTER_MESSAGE}"
  t.assert_include out, 'test failed'
  t.assert_not_include out, 'test is successful'
end

t.assert('config hooks - nginx -t rejects mruby_output_filter_code with the message of the removed directive', 'nginx -t') do
  out = nginx_t("http {\n    server {\n        location / {\n            mruby_output_filter_code 'Nginx.rputs 1';\n        }\n    }\n}")
  t.assert_include out, "[emerg] #{REMOVED_OUTPUT_FILTER_MESSAGE}"
  t.assert_include out, 'test failed'
  t.assert_not_include out, 'test is successful'
end

EXIT_HOOKS_PORT = 18158

def exit_hooks_prefix
  File.join(ENV['NGINX_INSTALL_DIR'], 'exit_hooks') + '/'
end

# ASAN_OPTIONS for the nginx -s quit process: it returns from main() without
# freeing the pool that main() creates first, so leak detection is off for
# it (see the stream-only test of test/t/ngx_mruby.rb). The nginx that runs
# the hooks keeps the options of the environment.
def exit_hooks_quit_asan_options
  asan = ENV['ASAN_OPTIONS'].to_s.split(':').reject { |o| o.start_with?('detect_leaks=') }
  asan << 'detect_leaks=0'
  asan.join(':')
end

def exit_hooks_conf
  install = ENV['NGINX_INSTALL_DIR']
  so = File.join(install, 'modules', 'ngx_http_mruby_module.so')
  prefix = exit_hooks_prefix
  # The computed values tell the lines of the hooks apart from anything else
  # in the log.
  <<CONF
#{File.exist?(so) ? "load_module #{so};" : ''}
daemon on;
master_process off;
worker_processes 1;
pid #{prefix}nginx.pid;
error_log #{prefix}error.log notice;
events { worker_connections 32; }
http {
    access_log off;
    mruby_exit_worker_code 'Nginx.log Nginx::LOG_NOTICE, "mruby_exit_worker_code ran: \#{6 * 7}"';
    server {
        listen 127.0.0.1:#{EXIT_HOOKS_PORT};
        location / {
            mruby_content_handler_code 'Nginx.rputs "exit hooks nginx is up"';
        }
    }
}
stream {
    # The stream block needs no server: the module opens the mrb_state of
    # the block when nginx creates its main configuration.
    mruby_stream_exit_worker_code 'Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "mruby_stream_exit_worker_code ran: \#{6 * 7}"';
}
CONF
end

# The pid of the nginx, or nil while its pid file is missing or empty.
def exit_hooks_pid
  pidfile = File.join(exit_hooks_prefix, 'nginx.pid')
  return nil unless File.exist?(pidfile)
  pid = File.read(pidfile).strip
  pid.empty? ? nil : pid
end

def exit_hooks_running?(pid)
  `kill -0 #{pid} 2>/dev/null && echo running`.strip == 'running'
end

# Waits up to 30 seconds, in steps of 0.2 seconds, until the block returns
# true, and returns what the block returned last.
def exit_hooks_wait
  150.times do
    return true if yield
    usleep 200000
  end
  yield
end

def exit_hooks_answer
  HttpRequest.new.get("#{base(EXIT_HOOKS_PORT)}/")["body"]
rescue
  nil
end

t.assert('config hooks - mruby_exit_worker_code and mruby_stream_exit_worker_code run at nginx -s quit', "127.0.0.1:#{EXIT_HOOKS_PORT}") do
  install = ENV['NGINX_INSTALL_DIR']
  nginx = File.join(install, 'sbin', 'nginx')
  prefix = exit_hooks_prefix
  conf = File.join(prefix, 'nginx.conf')
  log = File.join(prefix, 'error.log')
  `rm -rf #{prefix} && mkdir -p #{prefix}logs`
  File.open(conf, 'w') { |f| f.write exit_hooks_conf }

  started = `#{nginx} -p #{prefix} -c #{conf} 2>&1`
  up = exit_hooks_wait { exit_hooks_answer == 'exit hooks nginx is up' }
  pid = exit_hooks_pid
  quit = `ASAN_OPTIONS=#{exit_hooks_quit_asan_options} #{nginx} -p #{prefix} -c #{conf} -s quit 2>&1`
  # The process writes the lines of the exit hooks, removes its pid file and
  # exits; a sanitizer report would come last, at the exit.
  gone = pid ? exit_hooks_wait { !exit_hooks_running?(pid) } : false
  `kill -9 #{pid} 2>/dev/null` if pid && !gone
  lines = File.exist?(log) ? File.read(log).split("\n") : []
  sanitizer = lines.select { |l| l.include?('Sanitizer') || l.include?('runtime error:') }
  puts File.read(log) unless sanitizer.empty?

  t.assert_equal '', started
  t.assert_true up
  t.assert_equal '', quit
  t.assert_true gone
  t.assert_equal 1, lines.select { |l| l.include?('[notice]') && l.include?('mruby_exit_worker_code ran: 42') }.size
  t.assert_equal 1, lines.select { |l| l.include?('[notice]') && l.include?('mruby_stream_exit_worker_code ran: 42') }.size
  t.assert_equal [], sanitizer
end

t.report
