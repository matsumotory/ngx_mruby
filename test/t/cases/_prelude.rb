# Shared prelude for test/t/cases/*.rb. test.sh concatenates this file in
# front of each case before running it with the test build of mruby.

def http_host(port = 58080)
  "127.0.0.1:#{port}"
end

def base(port = 58080)
  "http://#{http_host(port)}"
end

def base_ssl(port)
  "https://localhost:#{port}"
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
def nginx_t(top_level)
  dir = ENV['NGINX_INSTALL_DIR']
  conf = File.join(dir, 'conf', 'nginx_t.conf')
  head = ''
  so = File.join(dir, 'modules', 'ngx_http_mruby_module.so')
  head = "load_module #{so};\n" if File.exist?(so)
  File.open(conf, 'w') do |f|
    f.write "#{head}events {}\n#{top_level}\n"
  end
  `#{dir}/sbin/nginx -t -c #{conf} -e #{File.join(dir, 'logs', 'nginx_t.log')} 2>&1`
end

# Raw TCP exchange through test/t/cases/_tcp_client.rb, which runs with CRuby.
# It returns the status of the connection (EOF, RESET, REFUSED or TIMEOUT)
# and the exact bytes received.
def tcp_client(port, payload = "")
  out = `ruby test/t/cases/_tcp_client.rb #{port} #{payload.unpack("H*")[0]}`
  status, hex = out.split(":", 2)
  [status, [hex.to_s].pack("H*")]
end

# Starts a second nginx through test/t/cases/_second_instance.rb, which runs
# with CRuby, and returns its "key=value" lines as a Hash. That file lists
# the keys.
def second_instance(mode)
  out = `ruby test/t/cases/_second_instance.rb #{mode}`
  result = {}
  out.split("\n").each do |line|
    key, value = line.split("=", 2)
    result[key] = value
  end
  result
end
