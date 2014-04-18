##
# Hash ISO Test

# location /mruby {
# location /hello {
# location /proxy {
# location / {
# location /headers {
# location /vars {
# location /redirect {
# location /redirect/internal {
# location /redirect/internal/dynamic/path {
# location /inter_var_file {
# location /inter_var_inline {
# location ~ \.rb$ {

base = 'http://127.0.0.1'

assert('ngx_mruby', 'location /mruby') do
  res = HttpRequest.new.get base + '/mruby'
  assert_equal 'Hello ngx_mruby/0.0.1 world!', res["body"]
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

