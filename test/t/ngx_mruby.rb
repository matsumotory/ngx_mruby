##
# ngx_mruby test

base = 'http://127.0.0.1:58080'

assert('ngx_mruby', 'location /mruby') do
  res = HttpRequest.new.get base + '/mruby'
  assert_equal 'Hello ngx_mruby world!', res["body"]
end

assert('ngx_mruby', 'location /proxy') do
  res = HttpRequest.new.get base + '/proxy'
  assert_equal 'proxy test ok', res["body"]
end

assert('ngx_mruby', 'location /vars') do
  res = HttpRequest.new.get base + '/vars'
  assert_equal 'host => 127.0.0.1 foo => mruby', res["body"]
end

assert('ngx_mruby', 'location /redirect') do
  res = HttpRequest.new.get base + '/redirect'
  assert_equal 301, res.code
  assert_equal 'http://ngx.mruby.org', res["location"]
end

assert('ngx_mruby', 'location /redirect/internal') do
  res = HttpRequest.new.get base + '/redirect/internal'
  assert_equal 'host => 127.0.0.1 foo => mruby', res["body"]
end

assert('ngx_mruby', 'location /inter_var_file') do
  res = HttpRequest.new.get base + '/inter_var_file'
  assert_equal 'fuga => 200 hoge => 400 hoge => 800', res["body"]
end

assert('ngx_mruby', 'location /inter_var_inline') do
  res = HttpRequest.new.get base + '/inter_var_inline'
  assert_equal 'fuga => 100 hoge => 200 hoge => 400', res["body"]
end

assert('ngx_mruby - output filter', 'location /filter_dynamic_arg') do
  res = HttpRequest.new.get base + '/filter_dynamic_arg'
  assert_equal 'output filter: static', res["body"]
end

assert('ngx_mruby - output filter', 'location /filter_dynamic_arg?hoge=fuga') do
  res = HttpRequest.new.get base + '/filter_dynamic_arg?hoge=fuga'
  assert_equal 'output filter: hoge=fuga', res["body"]
end

assert('ngx_mruby - Nginx::Connection#{local_ip,local_port}', 'location /server_ip_port') do
  res = HttpRequest.new.get base + '/server_ip_port'
  assert_equal '127.0.0.1:58080', res["body"]
end

assert('ngx_mruby - Nginx::Connection#{remote_ip,local_port}', 'location /client_ip') do
  res = HttpRequest.new.get base + '/client_ip'
  assert_equal '127.0.0.1', res["body"]
end

assert('ngx_mruby', 'location /header') do
  res1 = HttpRequest.new.get base + '/header'
  res2 = HttpRequest.new.get base + '/header', nil, {"X-REQUEST-HEADER" => "hoge"}

  assert_equal "X-REQUEST-HEADER not found", res1["body"]
  assert_equal "nothing", res1["x-response-header"]
  assert_equal "X-REQUEST-HEADER found", res2["body"]
  assert_equal "hoge", res2["x-response-header"]
end

assert('ngx_mruby - mruby_add_handler', '*\.rb') do
  res = HttpRequest.new.get base + '/add_handler.rb'
  assert_equal 'add_handler', res["body"]
end

assert('ngx_mruby - all instance test', 'location /all_instance') do
  res = HttpRequest.new.get base + '/all_instance'
  assert_equal "OK", res["x-inst-test"]
end

assert('ngx_mruby', 'location /request_method') do
  res = HttpRequest.new.get base + '/request_method'
  assert_equal "GET", res["body"]
  res = HttpRequest.new.post base + '/request_method'
  assert_equal "POST", res["body"]
  res = HttpRequest.new.head base + '/request_method'
  assert_equal "HEAD", res["body"]
end

assert('ngx_mruby - Kernel.server_name', 'location /kernel_servername') do
  res = HttpRequest.new.get base + '/kernel_servername'
  assert_equal 'NGINX', res["body"]
end

# see below url:
# https://github.com/matsumoto-r/ngx_mruby/wiki/Class-and-Method#refs-nginx-core-variables
assert('ngx_mruby - Nginx::Var', 'location /nginx_var?name=name') do
  assert_equal '/nginx_var', HttpRequest.new.get(base + '/nginx_var?name=uri')["body"]
  assert_equal 'HTTP/1.0', HttpRequest.new.get(base + '/nginx_var?name=server_protocol')["body"]
  assert_equal 'http', HttpRequest.new.get(base + '/nginx_var?name=scheme')["body"]
  assert_equal '127.0.0.1', HttpRequest.new.get(base + '/nginx_var?name=remote_addr')["body"]
  assert_equal '58080', HttpRequest.new.get(base + '/nginx_var?name=server_port')["body"]
  assert_equal '127.0.0.1', HttpRequest.new.get(base + '/nginx_var?name=server_addr')["body"]
  assert_equal 'GET /nginx_var?name=request HTTP/1.0', HttpRequest.new.get(base + '/nginx_var?name=request')["body"]
  assert_equal 'name=query_string', HttpRequest.new.get(base + '/nginx_var?name=query_string')["body"]
end

assert('ngx_mruby - Nginx.return', 'location /service_unavailable') do
  res = HttpRequest.new.get base + '/service_unavailable'
  assert_equal 503, res.code
end

# see below url:
