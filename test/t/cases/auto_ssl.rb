# The auto-ssl mrbgem (mrbgems/auto-ssl): Nginx::SSL::ACME::Dehydrated and
# Nginx::SSL::ACME::Client.
# Config: test/conf/conf.d/78-auto-ssl.conf (18171, and 18172 with TLS) in
# the test nginx, and test/auto_ssl/peer.conf (18173 and 18174) in a second
# nginx that this case starts with the prefix NGINX_INSTALL_DIR/auto_ssl/peer/
# and stops with "nginx -s quit", as test/t/cases/config_hooks.rb does.
#
# The case runs only when NGX_MRUBY_TEST_AUTO_SSL names the directory that
# "sh test/auto_ssl/deps.sh start DIR" prepared, and Redis, Pebble and its
# DNS server run (see "Testing the auto-ssl mrbgem" in docs/test/README.md).
# Without it, or in a build without the gem, the case prints why it skips
# and checks nothing.
#
# Nginx::SSL::ACME::Client#register and #auto_cert_deploy are not tested:
# they speak ACME v1 (new-reg, new-authz, new-cert), which Let's Encrypt
# turned off in 2021 and which Pebble does not implement.

t = SimpleTest.new "ngx_mruby test: auto-ssl mrbgem (Nginx::SSL::ACME)"

AUTO_SSL_DEPS = ENV['NGX_MRUBY_TEST_AUTO_SSL'].to_s
AUTO_SSL_DOMAIN = 'dehydrated.autossl.test'
AUTO_SSL_CLIENT_DOMAIN = 'client.autossl.test'
AUTO_SSL_OTHER_DOMAIN = 'other.autossl.test'
# The domain whose dehydrated configuration names the second Pebble, which
# requires external account binding, so that the registration fails.
AUTO_SSL_EAB_DOMAIN = 'eab.autossl.test'
AUTO_SSL_SECRET = 'auto-ssl-test-secret'
AUTO_SSL_PORT = 18171
AUTO_SSL_TLS_PORT = 18172
AUTO_SSL_HOOK_PORT = 18173
AUTO_SSL_CHALLENGE_PORT = 18174

def auto_ssl_dir
  File.join(ENV['NGINX_INSTALL_DIR'], 'auto_ssl')
end

# A path under NGINX_INSTALL_DIR/auto_ssl/ as 78-auto-ssl.conf writes it
# (__NGXDOCROOT__../auto_ssl/NAME), so that it matches the logged command.
def auto_ssl_conf_path(name)
  File.join(ENV['NGINX_INSTALL_DIR'], 'html') + "/../auto_ssl/#{name}"
end

def auto_ssl_peer_prefix
  File.join(auto_ssl_dir, 'peer') + '/'
end

def auto_ssl_log_path(name = 'error.log')
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', name)
end

def auto_ssl_log_size(name = 'error.log')
  File.exist?(auto_ssl_log_path(name)) ? File.size(auto_ssl_log_path(name)) : 0
end

# What nginx appended to the log after offset.
def auto_ssl_log_since(offset, name = 'error.log')
  return '' unless File.exist?(auto_ssl_log_path(name))
  File.open(auto_ssl_log_path(name)) do |f|
    f.seek(offset)
    f.read.to_s
  end
end

def auto_ssl_count(text, part)
  text.split(part, -1).size - 1
end

# The log is long, so a failure names only the text it looked for.
def auto_ssl_assert_logged(t, log, text)
  t.assert_true log.include?(text), "error.log has no line with: #{text}"
end

def auto_ssl_assert_not_logged(t, log, text)
  t.assert_false log.include?(text), "error.log has a line with: #{text}"
end

# Redis through test/t/cases/_redis_client.rb (CRuby).
def auto_ssl_redis_get(key)
  out = `ruby test/t/cases/_redis_client.rb get #{key}`.strip
  return nil if out == 'nil'
  raise "redis get #{key}: #{out}" unless out.start_with?('value:')
  [out[6..-1]].pack('H*')
end

def auto_ssl_redis_set(key, value)
  `ruby test/t/cases/_redis_client.rb set #{key} #{value.unpack('H*')[0]}`.strip
end

def auto_ssl_redis_del(keys)
  `ruby test/t/cases/_redis_client.rb del #{keys.join(' ')}`.strip
end

# The keys that the handlers of the gem read and write for a domain.
def auto_ssl_keys(domain)
  %w(.crt .key _token_filename _token_value _authorization_uri _private_key).map { |s| "#{domain}#{s}" }
end

# Waits up to 30 seconds, in steps of 0.2 seconds, until the block returns
# true, and returns what the block returned last.
def auto_ssl_wait
  150.times do
    return true if yield
    usleep 200000
  end
  yield
end

def auto_ssl_get(port, path)
  HttpRequest.new.get("#{base(port)}#{path}")
end

def auto_ssl_post(port, path, body, headers = {})
  HttpRequest.new.post("#{base(port)}#{path}", body, headers)
end

# The content of a file, or a text that says that it is missing.
def auto_ssl_read(path)
  File.exist?(path) ? File.read(path) : "(no file #{path})"
end

def auto_ssl_write(path, content)
  File.open(path, 'w') { |f| f.write content }
end

# The RSA modulus of a PEM key, as "openssl rsa -noout -modulus" prints it.
def auto_ssl_modulus(pem, name)
  path = File.join(auto_ssl_dir, 'direct', name)
  auto_ssl_write(path, pem)
  `openssl rsa -noout -modulus -in #{path} 2>&1`.strip
end

# curl, with the status and the exit code after the body:
# [exit code, HTTP status, body].
def auto_ssl_curl(args, max_time = 300)
  out_file = File.join(auto_ssl_dir, 'curl.out')
  `rm -f #{out_file}`
  status = `curl -4 -sS --max-time #{max_time} -o #{out_file} -w '%{http_code}' #{args} 2>#{out_file}.err; echo " $?"`
  code, exit_code = status.strip.split(' ')
  body = File.exist?(out_file) ? File.read(out_file) : ''
  [exit_code.to_i, code.to_i, body]
end

def auto_ssl_tls_request(domain, max_time = 300)
  auto_ssl_curl("--cacert #{File.join(auto_ssl_dir, 'pebble-root.pem')} " \
                "--resolve #{domain}:#{AUTO_SSL_TLS_PORT}:127.0.0.1 https://#{domain}:#{AUTO_SSL_TLS_PORT}/", max_time)
end

# The configuration of dehydrated: base is its directory under
# NGINX_INSTALL_DIR/auto_ssl/, port the ACME API of the Pebble to use.
def auto_ssl_dehydrated_conf(dir, base, port)
  <<CONF
CA="https://localhost:#{port}/dir"
CURL_OPTS="--cacert #{File.join(AUTO_SSL_DEPS, 'pebble.minica.pem')}"
IP_VERSION=4
BASEDIR="#{dir}/#{base}"
WELLKNOWN="#{dir}/#{base}/wellknown"
KEY_ALGO=rsa
KEYSIZE=2048
ACCOUNT_KEYSIZE=2048
CONF
end

def auto_ssl_peer_pid
  pidfile = File.join(auto_ssl_peer_prefix, 'nginx.pid')
  return nil unless File.exist?(pidfile)
  pid = File.read(pidfile).strip
  pid.empty? ? nil : pid
end

def auto_ssl_quit_asan_options
  asan = ENV['ASAN_OPTIONS'].to_s.split(':').reject { |o| o.start_with?('detect_leaks=') }
  asan << 'detect_leaks=0'
  asan.join(':')
end

def auto_ssl_built
  auto_ssl_get(AUTO_SSL_PORT, '/auto-ssl/built')['body']
rescue
  nil
end

def auto_ssl_peer_up
  auto_ssl_get(AUTO_SSL_HOOK_PORT, '/up')['body'] == 'auto-ssl peer is up'
rescue
  false
end

# Prepares NGINX_INSTALL_DIR/auto_ssl/, clears the keys of the test domains
# in Redis and starts the peer nginx. It returns what failed, or nil.
def auto_ssl_setup
  dir = auto_ssl_dir
  install = ENV['NGINX_INSTALL_DIR']
  `rm -rf #{dir} && mkdir -p #{dir}/base/wellknown #{dir}/base-eab/wellknown #{dir}/direct #{auto_ssl_peer_prefix}logs`
  `cp #{File.join(AUTO_SSL_DEPS, 'dehydrated')} #{dir}/dehydrated && cp test/auto_ssl/hook.sh #{dir}/hook.sh && chmod +x #{dir}/dehydrated #{dir}/hook.sh`
  return 'dehydrated or the hook was not copied' unless File.exist?("#{dir}/dehydrated") && File.exist?("#{dir}/hook.sh")
  auto_ssl_write("#{dir}/dehydrated.conf", auto_ssl_dehydrated_conf(dir, 'base', 14000))
  auto_ssl_write("#{dir}/dehydrated-eab.conf", auto_ssl_dehydrated_conf(dir, 'base-eab', 14001))

  keys = [AUTO_SSL_DOMAIN, AUTO_SSL_CLIENT_DOMAIN, AUTO_SSL_OTHER_DOMAIN, AUTO_SSL_EAB_DOMAIN].map { |d| auto_ssl_keys(d) }.flatten
  out = auto_ssl_redis_del(keys)
  return "Redis on 127.0.0.1:6379: #{out}" if out.start_with?('error:')

  # The root of the chain that Pebble issues; Pebble generates it when it
  # starts, and serves it on its management API.
  root = File.join(dir, 'pebble-root.pem')
  `curl -4 -sSf --max-time 30 --cacert #{File.join(AUTO_SSL_DEPS, 'pebble.minica.pem')} -o #{root} https://localhost:15000/roots/0 2>&1`
  return 'no root certificate from https://localhost:15000/roots/0' unless File.exist?(root) && File.read(root).include?('BEGIN CERTIFICATE')

  so = File.join(install, 'modules', 'ngx_http_mruby_module.so')
  conf = File.read('test/auto_ssl/peer.conf')
  conf = conf.split('__LOAD_MODULE__').join(File.exist?(so) ? "load_module #{so};" : '')
  conf = conf.split('__PREFIX__').join(auto_ssl_peer_prefix)
  conf = conf.split('__LOGS__').join(File.join(install, 'logs') + '/')
  conf_path = File.join(auto_ssl_peer_prefix, 'nginx.conf')
  auto_ssl_write(conf_path, conf)
  `rm -f #{auto_ssl_log_path('auto_ssl_peer.error.log')}`
  started = `#{install}/sbin/nginx -p #{auto_ssl_peer_prefix} -c #{conf_path} 2>&1`
  return "the peer nginx did not start: #{started}" unless started.empty?
  return 'the peer nginx does not answer on 18173' unless auto_ssl_wait { auto_ssl_peer_up }
  nil
end

# Stops the peer nginx and returns [whether it ended, sanitizer lines of its log].
def auto_ssl_teardown
  install = ENV['NGINX_INSTALL_DIR']
  pid = auto_ssl_peer_pid
  `ASAN_OPTIONS=#{auto_ssl_quit_asan_options} #{install}/sbin/nginx -p #{auto_ssl_peer_prefix} -c #{File.join(auto_ssl_peer_prefix, 'nginx.conf')} -s quit 2>&1`
  gone = pid ? auto_ssl_wait { `kill -0 #{pid} 2>/dev/null && echo running`.strip != 'running' } : false
  `kill -9 #{pid} 2>/dev/null` if pid && !gone
  log = auto_ssl_log_since(0, 'auto_ssl_peer.error.log')
  sanitizer = log.split("\n").select { |l| l.include?('Sanitizer') || l.include?('runtime error:') }
  puts log unless sanitizer.empty?
  [gone, sanitizer]
end

if AUTO_SSL_DEPS.empty?
  puts 'auto_ssl: skipped: NGX_MRUBY_TEST_AUTO_SSL is not set (see "Testing the auto-ssl mrbgem" in docs/test/README.md)'
elsif (built = auto_ssl_built) != 'true'
  puts "auto_ssl: skipped: the build has no auto-ssl mrbgem (GET /auto-ssl/built on #{AUTO_SSL_PORT} answered #{built.inspect})"
else
  setup_error = auto_ssl_setup
  t.assert('auto-ssl - the peer nginx, Redis and Pebble are ready', 'test/auto_ssl/deps.sh, 18173') do
    t.assert_equal nil, setup_error
  end

  if setup_error.nil?
    # Nginx::SSL::ACME::Client

    t.assert('auto-ssl - Client#allow_domain? is true only for a domain in allow_domains', "GET /auto-ssl/client/allow_domain on #{AUTO_SSL_PORT}") do
      t.assert_equal 'true', auto_ssl_get(AUTO_SSL_PORT, "/auto-ssl/client/allow_domain?domain=#{AUTO_SSL_CLIENT_DOMAIN}")['body']
      t.assert_equal 'false', auto_ssl_get(AUTO_SSL_PORT, "/auto-ssl/client/allow_domain?domain=#{AUTO_SSL_OTHER_DOMAIN}")['body']
    end

    stored_key = `openssl genrsa 2048 2>/dev/null`

    t.assert('auto-ssl - Client#private_key reads the key that Redis has for the domain, once', "GET /auto-ssl/client/private_key on #{AUTO_SSL_PORT}") do
      key_name = "#{AUTO_SSL_CLIENT_DOMAIN}_private_key"
      t.assert_equal 'OK', auto_ssl_redis_set(key_name, stored_key)
      res = auto_ssl_get(AUTO_SSL_PORT, '/auto-ssl/client/private_key')
      same, pem = res['body'].to_s.split("\n", 2)
      expected = auto_ssl_modulus(stored_key, 'stored.pem')
      t.assert_equal 200, res['code']
      t.assert_equal 'true', same
      t.assert_true expected.start_with?('Modulus=')
      t.assert_equal expected, auto_ssl_modulus(pem.to_s, 'returned.pem')
      t.assert_equal stored_key, auto_ssl_redis_get(key_name)
    end

    t.assert('auto-ssl - Client#private_key makes a 2048-bit key when Redis has none, and does not store it', "GET /auto-ssl/client/private_key on #{AUTO_SSL_PORT}") do
      key_name = "#{AUTO_SSL_CLIENT_DOMAIN}_private_key"
      auto_ssl_redis_del([key_name])
      res = auto_ssl_get(AUTO_SSL_PORT, '/auto-ssl/client/private_key')
      same, pem = res['body'].to_s.split("\n", 2)
      path = File.join(auto_ssl_dir, 'direct', 'new.pem')
      auto_ssl_write(path, pem.to_s)
      t.assert_equal 200, res['code']
      t.assert_equal 'true', same
      t.assert_include `openssl rsa -noout -text -in #{path} 2>&1`, 'Private-Key: (2048 bit'
      t.assert_not_equal auto_ssl_modulus(stored_key, 'stored.pem'), auto_ssl_modulus(pem.to_s, 'new.pem')
      t.assert_nil auto_ssl_redis_get(key_name)
    end

    t.assert('auto-ssl - Client#client reads the directory of the endpoint and signs with #private_key', "GET /auto-ssl/client/client on #{AUTO_SSL_PORT}") do
      auto_ssl_redis_set("#{AUTO_SSL_CLIENT_DOMAIN}_private_key", stored_key)
      res = auto_ssl_get(AUTO_SSL_PORT, '/auto-ssl/client/client')
      v1 = "http://127.0.0.1:#{AUTO_SSL_HOOK_PORT}/acme-v1"
      endpoints = %w(new-authz new-cert new-reg revoke-cert).map { |k| "#{k}=#{v1}/#{k}" }.join(',')
      t.assert_equal 200, res['code']
      t.assert_equal "Acme::Client|http://127.0.0.1:#{AUTO_SSL_HOOK_PORT}/|true|#{endpoints}", res['body']
    end

    t.assert('auto-ssl - Client#clear removes the token, the authorization URI and the private key of the domain', "GET /auto-ssl/client/clear on #{AUTO_SSL_PORT}") do
      d = AUTO_SSL_CLIENT_DOMAIN
      auto_ssl_redis_set("#{d}_token_value", 'token-value')
      auto_ssl_redis_set("#{d}_authorization_uri", 'http://127.0.0.1/authz')
      auto_ssl_redis_set("#{d}_private_key", stored_key)
      auto_ssl_redis_set("#{d}.crt", 'certificate')
      res = auto_ssl_get(AUTO_SSL_PORT, '/auto-ssl/client/clear')
      t.assert_equal 'cleared', res['body']
      t.assert_nil auto_ssl_redis_get("#{d}_token_value")
      t.assert_nil auto_ssl_redis_get("#{d}_authorization_uri")
      t.assert_nil auto_ssl_redis_get("#{d}_private_key")
      t.assert_equal 'certificate', auto_ssl_redis_get("#{d}.crt")
    end

    # Nginx::SSL::ACME::Dehydrated, one method at a time

    t.assert('auto-ssl - Dehydrated#allow_domain? is true only for a domain in allow_domains', "GET /auto-ssl/dehydrated/allow_domain on #{AUTO_SSL_PORT}") do
      t.assert_equal 'true', auto_ssl_get(AUTO_SSL_PORT, "/auto-ssl/dehydrated/allow_domain?domain=#{AUTO_SSL_DOMAIN}")['body']
      t.assert_equal 'false', auto_ssl_get(AUTO_SSL_PORT, "/auto-ssl/dehydrated/allow_domain?domain=#{AUTO_SSL_OTHER_DOMAIN}")['body']
    end

    t.assert('auto-ssl - Dehydrated.secret_token and .challenged_* read the header and the form of a hook request', "POST /auto-ssl/dehydrated/hook_request on #{AUTO_SSL_PORT}") do
      form = 'domain=a.autossl.test&token_filename=Tok_en-1&token_value=Tok_en-1.thumb'
      res = auto_ssl_post(AUTO_SSL_PORT, '/auto-ssl/dehydrated/hook_request', form, { 'X-Hook-Secret' => 's3cret' })
      t.assert_equal ['s3cret', 'a.autossl.test', 'Tok_en-1', 'Tok_en-1.thumb'].inspect, res['body']
      res = auto_ssl_post(AUTO_SSL_PORT, '/auto-ssl/dehydrated/hook_request', form)
      t.assert_equal [nil, 'a.autossl.test', 'Tok_en-1', 'Tok_en-1.thumb'].inspect, res['body']
    end

    t.assert('auto-ssl - Dehydrated.token_filename_from_url returns the last path segment of a challenge URL, or nil', "GET /.well-known/acme-challenge/ on #{AUTO_SSL_PORT}") do
      t.assert_equal '"Tok_en-1"', auto_ssl_get(AUTO_SSL_PORT, '/.well-known/acme-challenge/Tok_en-1')['body']
      t.assert_equal 'nil', auto_ssl_get(AUTO_SSL_PORT, '/.well-known/acme-challenge/not.a.token')['body']
    end

    t.assert('auto-ssl - Dehydrated.deploy_cert_information reads the key and the full chain that the hook names', "POST /auto-ssl/dehydrated/deploy_cert_information on #{AUTO_SSL_PORT}") do
      key = File.join(auto_ssl_dir, 'direct', 'privkey.pem')
      crt = File.join(auto_ssl_dir, 'direct', 'fullchain.pem')
      auto_ssl_write(key, "key of a.autossl.test\n")
      auto_ssl_write(crt, "chain of a.autossl.test\n")
      res = auto_ssl_post(AUTO_SSL_PORT, '/auto-ssl/dehydrated/deploy_cert_information', "domain=a.autossl.test&privkey=#{key}&cert=#{crt}.unused&fullchain=#{crt}")
      t.assert_equal 200, res['code']
      t.assert_equal [%w(crt domain key).inspect, 'a.autossl.test', "key of a.autossl.test\n", "chain of a.autossl.test\n"].inspect, res['body']
    end

    t.assert('auto-ssl - Dehydrated.deploy_cert_information raises when the key or the full chain is missing', "POST /auto-ssl/dehydrated/deploy_cert_information on #{AUTO_SSL_PORT}") do
      key = File.join(auto_ssl_dir, 'direct', 'privkey.pem')
      crt = File.join(auto_ssl_dir, 'direct', 'fullchain.pem')
      missing = File.join(auto_ssl_dir, 'direct', 'missing.pem')
      offset = auto_ssl_log_size
      res1 = auto_ssl_post(AUTO_SSL_PORT, '/auto-ssl/dehydrated/deploy_cert_information', "domain=a.autossl.test&privkey=#{missing}&fullchain=#{crt}")
      res2 = auto_ssl_post(AUTO_SSL_PORT, '/auto-ssl/dehydrated/deploy_cert_information', "domain=a.autossl.test&privkey=#{key}&fullchain=#{missing}")
      log = auto_ssl_log_since(offset)
      t.assert_equal 500, res1['code']
      t.assert_equal 500, res2['code']
      auto_ssl_assert_logged t, log, "not found key file: #{missing}"
      auto_ssl_assert_logged t, log, "not found crt file: #{missing}"
    end

    t.assert('auto-ssl - the hook server refuses a request without the secret', "POST /deploy-challenge and /deploy-cert on #{AUTO_SSL_HOOK_PORT}") do
      form = "domain=#{AUTO_SSL_OTHER_DOMAIN}&token_filename=t&token_value=t.v"
      res1 = auto_ssl_post(AUTO_SSL_HOOK_PORT, '/deploy-challenge', form, { 'X-Hook-Secret' => 'wrong' })
      res2 = auto_ssl_post(AUTO_SSL_HOOK_PORT, '/deploy-cert', "domain=#{AUTO_SSL_OTHER_DOMAIN}&privkey=/nonexistent&fullchain=/nonexistent")
      t.assert_equal 401, res1['code']
      t.assert_equal 401, res2['code']
      t.assert_nil auto_ssl_redis_get("#{AUTO_SSL_OTHER_DOMAIN}_token_filename")
    end

    # Nginx::SSL::ACME::Dehydrated#auto_cert_deploy in the TLS handshake,
    # with dehydrated, Pebble, and the hook and challenge servers of the peer
    # nginx. The dehydrated account does not exist yet: the first run of
    # dehydrated asks for the terms of service, #auto_accept_terms registers
    # the account, and the second run gets the certificate.

    t.assert('auto-ssl - Dehydrated#auto_cert_deploy gets a certificate from Pebble during the handshake', "TLS to #{AUTO_SSL_DOMAIN} on #{AUTO_SSL_TLS_PORT}") do
      dir = auto_ssl_dir
      d = AUTO_SSL_DOMAIN
      command = "run acme command: #{auto_ssl_conf_path('dehydrated')} --cron --lock-suffix #{d} --domain #{d} " \
                "--challenge http-01 --hook #{auto_ssl_conf_path('hook.sh')} --config #{auto_ssl_conf_path('dehydrated.conf')}"
      offset = auto_ssl_log_size
      exit_code, code, body = auto_ssl_tls_request(d)
      log = auto_ssl_log_since(offset)
      puts File.read(File.join(dir, 'curl.out.err')) if exit_code != 0

      t.assert_equal 0, exit_code
      t.assert_equal 200, code
      t.assert_equal "hello #{d} from auto-ssl", body
      # One run that stops at the terms of service, one that gets the
      # certificate after #auto_accept_terms.
      t.assert_equal 2, auto_ssl_count(log, command)
      auto_ssl_assert_logged t, log, '+ Registering account key with ACME server...'
      t.assert_true `ls #{dir}/base/accounts/*/registration_info.json 2>/dev/null`.strip.end_with?('registration_info.json')

      # What the hooks stored: the files of dehydrated, through
      # .deploy_cert_information, and the challenge, through .challenged_*.
      certdir = File.join(dir, 'base', 'certs', d)
      t.assert_equal auto_ssl_read(File.join(certdir, 'fullchain.pem')), auto_ssl_redis_get("#{d}.crt")
      t.assert_equal auto_ssl_read(File.join(certdir, 'privkey.pem')), auto_ssl_redis_get("#{d}.key")
      filename = auto_ssl_redis_get("#{d}_token_filename").to_s
      value = auto_ssl_redis_get("#{d}_token_value").to_s
      t.assert_true filename.size > 20
      t.assert_true value.start_with?("#{filename}.")
      t.assert_true value.size > filename.size + 20
    end

    t.assert('auto-ssl - the challenge server answers the token that Pebble validated, and 404 for another', "GET /.well-known/acme-challenge/ on #{AUTO_SSL_CHALLENGE_PORT}") do
      d = AUTO_SSL_DOMAIN
      filename = auto_ssl_redis_get("#{d}_token_filename").to_s
      _exit_code, code, body = auto_ssl_curl("-H 'Host: #{d}' http://127.0.0.1:#{AUTO_SSL_CHALLENGE_PORT}/.well-known/acme-challenge/#{filename}")
      t.assert_equal 200, code
      t.assert_equal auto_ssl_redis_get("#{d}_token_value"), body
      code = auto_ssl_curl("-H 'Host: #{d}' http://127.0.0.1:#{AUTO_SSL_CHALLENGE_PORT}/.well-known/acme-challenge/other-token")[1]
      t.assert_equal 404, code
    end

    t.assert('auto-ssl - a later handshake uses the certificate in Redis without dehydrated', "TLS to #{AUTO_SSL_DOMAIN} on #{AUTO_SSL_TLS_PORT}") do
      offset = auto_ssl_log_size
      exit_code, code, body = auto_ssl_tls_request(AUTO_SSL_DOMAIN)
      log = auto_ssl_log_since(offset)
      t.assert_equal 0, exit_code
      t.assert_equal 200, code
      t.assert_equal "hello #{AUTO_SSL_DOMAIN} from auto-ssl", body
      auto_ssl_assert_not_logged t, log, 'run acme command: '
    end

    t.assert('auto-ssl - the handshake of a domain outside allow_domains fails before dehydrated runs', "TLS to #{AUTO_SSL_OTHER_DOMAIN} on #{AUTO_SSL_TLS_PORT}") do
      offset = auto_ssl_log_size
      exit_code = auto_ssl_tls_request(AUTO_SSL_OTHER_DOMAIN)[0]
      log = auto_ssl_log_since(offset)
      t.assert_not_equal 0, exit_code
      auto_ssl_assert_logged t, log, "not allowed servername: #{AUTO_SSL_OTHER_DOMAIN}"
      auto_ssl_assert_not_logged t, log, 'run acme command: '
      t.assert_nil auto_ssl_redis_get("#{AUTO_SSL_OTHER_DOMAIN}.crt")
    end

    # dehydrated 0.5.0 and later remove the account key that they made when
    # the registration fails, so the next run asks for the terms of service
    # again. #auto_cert_deploy accepts them once per call, and returns
    # without a certificate when dehydrated asks again. The limit of curl
    # is short, because the handshake takes a few seconds when the method
    # stops, and blocks the test nginx as long as it does not.
    t.assert('auto-ssl - Dehydrated#auto_cert_deploy accepts the terms of service once when the registration fails', "TLS to #{AUTO_SSL_EAB_DOMAIN} on #{AUTO_SSL_TLS_PORT}") do
      dir = auto_ssl_dir
      d = AUTO_SSL_EAB_DOMAIN
      command = "run acme command: #{auto_ssl_conf_path('dehydrated')} --cron --lock-suffix #{d} --domain #{d} " \
                "--challenge http-01 --hook #{auto_ssl_conf_path('hook.sh')} --config #{auto_ssl_conf_path('dehydrated-eab.conf')}"
      offset = auto_ssl_log_size
      exit_code = auto_ssl_tls_request(d, 60)[0]
      log = auto_ssl_log_since(offset)
      t.assert_not_equal 0, exit_code
      t.assert_equal 2, auto_ssl_count(log, command)
      t.assert_equal 1, auto_ssl_count(log, 'This CA requires an external account')
      t.assert_equal '', `find #{dir}/base-eab/accounts -type f 2>/dev/null`.strip
      t.assert_nil auto_ssl_redis_get("#{d}.crt")
    end
  end

  gone, sanitizer = auto_ssl_teardown
  t.assert('auto-ssl - the peer nginx stops at nginx -s quit with no sanitizer report', 'nginx -s quit') do
    t.assert_true gone
    t.assert_equal [], sanitizer
  end
end

t.report
