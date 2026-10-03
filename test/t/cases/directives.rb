# File versions of the phase handler directives, mruby_cache, and the file
# versions of mruby_init and mruby_init_worker.
# Config: test/conf/conf.d/30-directives.conf (ports 58114 and 58115) and the
# init lines of test/conf/nginx.conf. Hooks: test/html/directives_*.rb.

t = SimpleTest.new "ngx_mruby test: directive file versions"

# Writes a small configuration and runs "nginx -t" on it, so that cases can
# check how nginx parses a directive without touching the running server.
def g3_nginx_t(http_body)
  dir = ENV['NGINX_INSTALL_DIR']
  conf = File.join(dir, 'conf', 'g3_nginx_t.conf')
  head = ''
  so = File.join(dir, 'modules', 'ngx_http_mruby_module.so')
  head = "load_module #{so};\n" if File.exist?(so)
  File.open(conf, 'w') do |f|
    f.write "#{head}events {}\nhttp {\n#{http_body}\n}\n"
  end
  `#{dir}/sbin/nginx -t -c #{conf} -e #{File.join(dir, 'logs', 'g3_nginx_t.log')} 2>&1`
end

def g3_html(name)
  File.join(ENV['NGINX_INSTALL_DIR'], 'html', name)
end

t.assert('directives - file hooks run in phase order', 'post_read, server_rewrite, rewrite and access on 58114 /g3/chain') do
  res = HttpRequest.new.get base(58114) + '/g3/chain'
  t.assert_equal 200, res.code
  t.assert_equal 'post_read,server_rewrite,rewrite,access', res["body"]
end

t.assert('directives - mruby_access_handler file rejects with 403', 'location /g3/chain?deny=1') do
  res = HttpRequest.new.get base(58114) + '/g3/chain?deny=1'
  t.assert_equal 403, res.code
  t.assert_include res["body"], '<title>403 Forbidden</title>'
  t.assert_not_include res["body"], 'post_read'
end

# characterizes v2 behaviour; see docs/proposals/v3-plan.md
# In the access phase the inline hook runs before the file hook, because
# ngx_http_mruby_handler_init registers the inline handler second and nginx
# runs the handlers of a phase in reverse order of registration.
t.assert('directives - inline access hook runs before the file access hook', 'location /g3/access_order') do
  res = HttpRequest.new.get base(58114) + '/g3/access_order'
  t.assert_equal 200, res.code
  t.assert_equal 'post_read,server_rewrite,access_inline,access', res["body"]
end

# characterizes v2 behaviour; see docs/proposals/v3-plan.md
# In the log phase nginx runs the handlers in order of registration, so the
# file hook runs before the inline hook, the reverse of the access phase.
t.assert('directives - mruby_log_handler and mruby_log_handler_code store values for the next request', 'location /g3/log') do
  res1 = HttpRequest.new.get base(58114) + '/g3/log?n=1'
  read1 = HttpRequest.new.get base(58114) + '/g3/log_read'
  res2 = HttpRequest.new.get base(58114) + '/g3/log?n=2'
  read2 = HttpRequest.new.get base(58114) + '/g3/log_read'
  t.assert_equal 'log target', res1["body"]
  t.assert_equal 'log target', res2["body"]
  t.assert_equal 'file /g3/log?n=1 200|inline', read1["body"]
  t.assert_equal 'file /g3/log?n=2 200|inline', read2["body"]
end

t.assert('directives - mruby_cache keeps the compiled file hook', 'locations /g3/cache/* on 58114 and /g3/srv_cache on 58115') do
  fname = g3_html('directives_cache.rb')
  original = File.read(fname)
  urls = [
    base(58114) + '/g3/cache/on',
    base(58114) + '/g3/cache/arg',
    base(58115) + '/g3/srv_cache',
    base(58114) + '/g3/cache/off',
  ]
  before = urls.map { |u| HttpRequest.new.get(u)["body"] }
  begin
    File.open(fname, 'w') { |f| f.write original.gsub('cache-v1', 'cache-v2') }
    changed = urls.map { |u| HttpRequest.new.get(u)["body"] }
  ensure
    File.open(fname, 'w') { |f| f.write original }
  end
  restored = urls.map { |u| HttpRequest.new.get(u)["body"] }
  t.assert_equal ['cache-v1', 'cache-v1', 'cache-v1', 'cache-v1'], before
  # Only the location without any cache setting reads the file again.
  t.assert_equal ['cache-v1', 'cache-v1', 'cache-v1', 'cache-v2'], changed
  t.assert_equal ['cache-v1', 'cache-v1', 'cache-v1', 'cache-v1'], restored
end

t.assert('directives - mruby_init and mruby_init_worker files ran in order', 'location /g3/init') do
  res = HttpRequest.new.get base(58114) + '/g3/init'
  t.assert_equal 200, res.code
  t.assert_equal 'init,init_worker', res["body"]
end

# characterizes v2 behaviour; see docs/proposals/v3-plan.md
# nginx accepts mruby_server_rewrite_handler inside a location, but the
# server rewrite phase reads the server level configuration, so the hook
# never runs and the trace header stays empty.
t.assert('directives - mruby_server_rewrite_handler inside a location does not run', 'location /g3/server_rewrite_in_location on 58115') do
  res = HttpRequest.new.get base(58115) + '/g3/server_rewrite_in_location'
  t.assert_equal 200, res.code
  t.assert_equal 'trace=', res["body"]
end

# characterizes v2 behaviour; see docs/proposals/v3-plan.md
t.assert('directives - mruby_init and mruby_init_code cannot both be set', 'nginx -t') do
  out = g3_nginx_t("mruby_init #{g3_html('directives_init.rb')};\nmruby_init_code 'true';")
  t.assert_include out, '"mruby_init_code" directive is duplicated'
  t.assert_include out, 'test failed'
end

# characterizes v2 behaviour; see docs/proposals/v3-plan.md
t.assert('directives - mruby_init_worker and mruby_init_worker_code cannot both be set', 'nginx -t') do
  out = g3_nginx_t("mruby_init_worker_code 'true';\nmruby_init_worker #{g3_html('directives_init_worker.rb')};")
  t.assert_include out, '"mruby_init_worker" directive is duplicated'
  t.assert_include out, 'test failed'
end

t.assert('directives - mruby_exit_worker file version is accepted', 'nginx -t') do
  out = g3_nginx_t("mruby_exit_worker #{g3_html('exit_worker.rb')};")
  t.assert_include out, 'test is successful'
end

t.assert('directives - mruby_post_read_handler is rejected inside a location', 'nginx -t') do
  out = g3_nginx_t("server {\nlisten 58115;\nlocation / {\nmruby_post_read_handler #{g3_html('directives_post_read.rb')};\n}\n}")
  t.assert_include out, '"mruby_post_read_handler" directive is not allowed here'
  t.assert_include out, 'test failed'
end

t.assert('directives - only "cache" is accepted as the second argument', 'nginx -t') do
  out = g3_nginx_t("server {\nlisten 58115;\nlocation / {\nmruby_access_handler #{g3_html('directives_access.rb')} nocache;\n}\n}")
  t.assert_include out, 'invalid parameter "nocache", valid parameter is only "cache"'
  t.assert_include out, 'test failed'
end

t.assert('directives - a missing hook file stops the configuration', 'nginx -t') do
  missing = g3_html('directives_missing.rb')
  out = g3_nginx_t("server {\nlisten 58115;\nlocation / {\nmruby_rewrite_handler #{missing};\n}\n}")
  t.assert_include out, "mrb_file(#{missing}) open failed"
  t.assert_include out, 'test failed'
end

t.report
