# File versions of the phase handler directives, mruby_cache, and the file
# versions of mruby_init, mruby_init_worker and mruby_exit_worker.
# Config: test/conf/conf.d/30-directives.conf (ports 58114 and 58115).
# Hooks: test/html/directives_*.rb. nginx_t, html_path and second_instance
# are in test/t/cases/_prelude.rb. The second nginx of
# test/t/cases/_second_instance.rb listens on port 58116.

t = SimpleTest.new "ngx_mruby test: directive file versions"

def nginx_t_http(http_body)
  nginx_t("http {\n#{http_body}\n}")
end

t.assert('directives - file hooks run in phase order', 'post_read, server_rewrite, rewrite and access on 58114 /directives/chain') do
  res = HttpRequest.new.get base(58114) + '/directives/chain'
  t.assert_equal 200, res.code
  t.assert_equal 'post_read,server_rewrite,rewrite,access', res["body"]
end

t.assert('directives - mruby_access_handler file rejects with 403', 'location /directives/chain?deny=1') do
  res = HttpRequest.new.get base(58114) + '/directives/chain?deny=1'
  t.assert_equal 403, res.code
  t.assert_include res["body"], '<title>403 Forbidden</title>'
  # The hooks of the earlier phases ran before the access hook rejected the
  # request.
  trace = HttpRequest.new.get base(58114) + '/directives/denied_trace'
  t.assert_equal 'post_read,server_rewrite,rewrite', trace["body"]
end

# characterizes v2 behaviour; see docs/proposals/v3-plan.md
# In the access phase the inline hook runs before the file hook, because
# ngx_http_mruby_handler_init registers the inline handler second and nginx
# runs the handlers of a phase in reverse order of registration.
t.assert('directives - inline access hook runs before the file access hook', 'location /directives/access_order') do
  res = HttpRequest.new.get base(58114) + '/directives/access_order'
  t.assert_equal 200, res.code
  t.assert_equal 'post_read,server_rewrite,access_inline,access', res["body"]
end

# characterizes v2 behaviour; see docs/proposals/v3-plan.md
# In the log phase nginx runs the handlers in order of registration, so the
# file hook runs before the inline hook, the reverse of the access phase.
t.assert('directives - mruby_log_handler and mruby_log_handler_code store values for the next request', 'location /directives/log') do
  res1 = HttpRequest.new.get base(58114) + '/directives/log?n=1'
  read1 = HttpRequest.new.get base(58114) + '/directives/log_read'
  res2 = HttpRequest.new.get base(58114) + '/directives/log?n=2'
  read2 = HttpRequest.new.get base(58114) + '/directives/log_read'
  t.assert_equal 'log target', res1["body"]
  t.assert_equal 'log target', res2["body"]
  t.assert_equal 'file /directives/log?n=1 200|inline', read1["body"]
  t.assert_equal 'file /directives/log?n=2 200|inline', read2["body"]
end

t.assert('directives - mruby_cache keeps the compiled file hook', 'locations /directives/cache/* on 58114 and /directives/cache/server on 58115') do
  fname = html_path('directives_cache.rb')
  original = File.read(fname)
  urls = [
    base(58114) + '/directives/cache/on',
    base(58114) + '/directives/cache/arg',
    base(58115) + '/directives/cache/server',
    base(58114) + '/directives/cache/off',
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

# characterizes v2 behaviour; see docs/proposals/v3-plan.md
# ngx_http_mruby_init runs the mruby_init hook in postconfiguration, so
# nginx -t runs it. The init_worker hook runs only in a started worker.
t.assert('directives - nginx -t runs the mruby_init file and not the mruby_init_worker file', 'nginx -t') do
  out = nginx_t_http("mruby_init #{html_path('directives_init.rb')};\nmruby_init_worker #{html_path('directives_init_worker.rb')};")
  t.assert_include out, 'test is successful'
  t.assert_include out, '"mruby_init file"'
  t.assert_not_include out, '"mruby_init_worker file"'
end

# The second nginx loads the file versions of mruby_init, mruby_init_worker
# and mruby_exit_worker. The reply shows that the global variable set by the
# init file reached the init_worker file and a request. The p lines show
# the order of the three hooks, the last one printed when nginx stopped.
# The second nginx runs without valgrind in every cell, so this case also
# runs in the valgrind cells.
t.assert('directives - mruby_init, mruby_init_worker and mruby_exit_worker files in a second nginx', '127.0.0.1:58116') do
  r = second_instance('http')
  t.assert_nil r['error']
  t.assert_nil r['sanitizer']
  t.assert_equal 'init,init_worker', r['reply']
  t.assert_equal '"mruby_init file"|"mruby_init_worker file"|"mruby_exit_worker file"', r['stdout']
  t.assert_equal 'exited 0', r['exit']
end

# characterizes v2 behaviour; see docs/proposals/v3-plan.md
# nginx accepts mruby_server_rewrite_handler inside a location, but the
# server rewrite phase reads the server level configuration, so the hook
# never runs and the trace header stays empty.
t.assert('directives - mruby_server_rewrite_handler inside a location does not run', 'location /directives/server_rewrite_in_location on 58115') do
  res = HttpRequest.new.get base(58115) + '/directives/server_rewrite_in_location'
  t.assert_equal 200, res.code
  t.assert_equal 'trace=', res["body"]
end

# characterizes v2 behaviour; see docs/proposals/v3-plan.md
t.assert('directives - mruby_init and mruby_init_code cannot both be set', 'nginx -t') do
  out = nginx_t_http("mruby_init #{html_path('directives_init.rb')};\nmruby_init_code 'true';")
  t.assert_include out, '"mruby_init_code" directive is duplicated'
  t.assert_include out, 'test failed'
end

# characterizes v2 behaviour; see docs/proposals/v3-plan.md
t.assert('directives - mruby_init_worker and mruby_init_worker_code cannot both be set', 'nginx -t') do
  out = nginx_t_http("mruby_init_worker_code 'true';\nmruby_init_worker #{html_path('directives_init_worker.rb')};")
  t.assert_include out, '"mruby_init_worker" directive is duplicated'
  t.assert_include out, 'test failed'
end

t.assert('directives - mruby_exit_worker file version is accepted', 'nginx -t') do
  out = nginx_t_http("mruby_exit_worker #{html_path('exit_worker.rb')};")
  t.assert_include out, 'test is successful'
end

t.assert('directives - mruby_post_read_handler is rejected inside a location', 'nginx -t') do
  out = nginx_t_http("server {\nlisten 58115;\nlocation / {\nmruby_post_read_handler #{html_path('directives_post_read.rb')};\n}\n}")
  t.assert_include out, '"mruby_post_read_handler" directive is not allowed here'
  t.assert_include out, 'test failed'
end

t.assert('directives - only "cache" is accepted as the second argument', 'nginx -t') do
  out = nginx_t_http("server {\nlisten 58115;\nlocation / {\nmruby_access_handler #{html_path('directives_access.rb')} nocache;\n}\n}")
  t.assert_include out, 'invalid parameter "nocache", valid parameter is only "cache"'
  t.assert_include out, 'test failed'
end

t.assert('directives - a missing hook file stops the configuration', 'nginx -t') do
  missing = html_path('directives_missing.rb')
  out = nginx_t_http("server {\nlisten 58115;\nlocation / {\nmruby_rewrite_handler #{missing};\n}\n}")
  t.assert_include out, "mrb_file(#{missing}) open failed"
  t.assert_include out, 'test failed'
end

t.report
