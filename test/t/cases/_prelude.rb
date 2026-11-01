# Shared prelude for test/t/cases/*.rb. test.sh concatenates this file in
# front of each case before running it with the test build of mruby.

def http_host(port = 18080)
  "127.0.0.1:#{port}"
end

def base(port = 18080)
  "http://#{http_host(port)}"
end

def base_ssl(port)
  "https://localhost:#{port}"
end

# Path of a file of the suite in the copy that test.sh runs, in which every
# port is moved by TEST_SH_PORT_OFFSET (test/t/cases/_stage.rb), for example
# suite_path('test/t/cases/_tcp_client.rb'). Without TEST_SH_STAGE_DIR, as
# when a case runs outside test.sh, it is the path in the checkout.
def suite_path(path)
  File.join(ENV['TEST_SH_STAGE_DIR'] || '.', path)
end

# Path of a file that test.sh copied from test/html into the installed nginx.
def html_path(name)
  File.join(ENV['NGINX_INSTALL_DIR'], 'html', name)
end

# Writes a configuration with the given top level blocks and runs "nginx -t"
# on it, so that a case can check how nginx reads directives without touching
# the running server. It returns what nginx and the mruby hooks printed. A
# dynamic module build loads the module with an absolute path. nginx -t runs
# the postconfiguration and init_module handlers, so mruby_init and
# mruby_stream_init run here, and the init_worker hooks do not.
#
# nginx -t returns from main() without destroying the cycle, so in a build
# with AddressSanitizer every configuration allocation of nginx itself is
# reported as a leak at exit, the report is appended to the output and the
# exit status changes. Leak detection is therefore turned off for this run
# only; the other sanitizer checks stay on, and the running server is still
# checked for leaks when it exits.
def nginx_t(top_level)
  dir = ENV['NGINX_INSTALL_DIR']
  conf = File.join(dir, 'conf', 'nginx_t.conf')
  head = ''
  so = File.join(dir, 'modules', 'ngx_http_mruby_module.so')
  head = "load_module #{so};\n" if File.exist?(so)
  File.open(conf, 'w') do |f|
    f.write "#{head}events {}\n#{top_level}\n"
  end
  asan = ENV['ASAN_OPTIONS'].to_s.split(':').reject { |o| o.start_with?('detect_leaks=') }
  asan << 'detect_leaks=0'
  `ASAN_OPTIONS=#{asan.join(':')} #{dir}/sbin/nginx -t -c #{conf} -e #{File.join(dir, 'logs', 'nginx_t.log')} 2>&1`
end

# Raw TCP exchange through test/t/cases/_tcp_client.rb, which runs with CRuby.
# It returns the status of the connection (EOF, RESET, REFUSED or TIMEOUT)
# and the exact bytes received. A later payload is written 0.3 seconds after
# the first one.
def tcp_client(port, payload = "", later = nil)
  args = "#{port} #{payload.unpack("H*")[0]}"
  args += " #{later.unpack("H*")[0]}" if later
  out = `ruby #{suite_path('test/t/cases/_tcp_client.rb')} #{args}`
  status, hex = out.split(":", 2)
  [status, [hex.to_s].pack("H*")]
end

# Starts a second nginx through test/t/cases/_second_instance.rb, which runs
# with CRuby, and returns its "key=value" lines as a Hash. That file lists
# the keys.
def second_instance(mode)
  out = `ruby #{suite_path('test/t/cases/_second_instance.rb')} #{mode}`
  result = {}
  out.split("\n").each do |line|
    key, value = line.split("=", 2)
    result[key] = value
  end
  result
end

# Runs nginx with a master process and several worker processes through
# test/t/cases/_workers.rb, which runs with CRuby, in one of its modes
# (isolation, reload), and returns its "key=value" lines as a Hash of each
# key to the Array of its values, in order. That file lists the keys.
def workers_nginx(mode)
  out = `ruby #{suite_path('test/t/cases/_workers.rb')} #{mode}`
  result = {}
  out.split("\n").each do |line|
    key, value = line.split("=", 2)
    (result[key] ||= []) << value.to_s
  end
  result
end
