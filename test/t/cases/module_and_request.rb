# Nginx.module_version, Nginx.nginx_version, Nginx.server_version,
# Nginx::Request#content_type, #content_type=, #method=, #scheme and
# #document_root, and Nginx::SSL.log.
# Config: test/conf/conf.d/70-module-and-request.conf (ports 18155 and 18156).

t = SimpleTest.new "ngx_mruby test: module functions and request accessors"

def module_and_request_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

# Lines that nginx appended to error.log after offset.
def module_and_request_log_lines(offset)
  File.open(module_and_request_log_path) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
end

# The version that "nginx -v" prints, as in "nginx version: nginx/1.31.6".
# nginx -v returns from main() early; leak detection is turned off for that
# process only, as nginx_t in test/t/cases/_prelude.rb does for nginx -t.
def module_and_request_nginx_v
  asan = ENV['ASAN_OPTIONS'].to_s.split(':').reject { |o| o.start_with?('detect_leaks=') }
  asan << 'detect_leaks=0'
  out = `ASAN_OPTIONS=#{asan.join(':')} #{ENV['NGINX_INSTALL_DIR']}/sbin/nginx -v 2>&1`
  out.split('nginx version: nginx/', 2)[1].to_s.strip
end

# The test build of mruby has no Regexp, so the parts are checked one by one.
def module_and_request_dotted_number?(s)
  parts = s.split('.')
  parts.size == 3 && parts.all? { |part| !part.empty? && part.to_i.to_s == part }
end

t.assert('Nginx.module_version is MODULE_VERSION of the module', 'GET /module/versions on 18155') do
  header = File.read('src/http/ngx_http_mruby_module.h')
  line = header.split("\n").find { |l| l.start_with?('#define MODULE_VERSION "') }
  expected = line.to_s.split('"')[1]
  t.assert_true module_and_request_dotted_number?(expected.to_s)
  res = HttpRequest.new.get base(18155) + '/module/versions'
  t.assert_equal 200, res.code
  module_version, _, _ = res["body"].split("|")
  t.assert_equal expected, module_version
end

t.assert('Nginx.nginx_version and Nginx.server_version are the version of nginx -v and of the Server header', 'GET /module/versions on 18155') do
  version = module_and_request_nginx_v
  t.assert_true module_and_request_dotted_number?(version)
  res = HttpRequest.new.get base(18155) + '/module/versions'
  t.assert_equal 200, res.code
  _, nginx_version, server_version = res["body"].split("|")
  t.assert_equal version, nginx_version
  t.assert_equal version, server_version
  t.assert_equal "nginx/#{version}", res["server"]
end

t.assert('Nginx::Request#content_type= sets the Content-Type of the response, and #content_type reads it', 'GET /request/content_type on 18155') do
  res = HttpRequest.new.get base(18155) + '/request/content_type'
  t.assert_equal 200, res.code
  t.assert_equal '["", "text/x-ngx-mruby-test"]', res["body"]
  t.assert_equal 'text/x-ngx-mruby-test', res["content-type"]
end

t.assert('Nginx::Request#method= in the rewrite phase changes the getter and $request_method', 'GET /request/method_set on 18155') do
  res = HttpRequest.new.get base(18155) + '/request/method_set'
  t.assert_equal 200, res.code
  t.assert_equal 'POST|POST', res["body"]
end

t.assert('Nginx::Request#scheme is http on a plain listener', 'GET /request/scheme on 18155') do
  res = HttpRequest.new.get base(18155) + '/request/scheme'
  t.assert_equal 200, res.code
  t.assert_equal 'http|http', res["body"]
end

t.assert('Nginx::Request#scheme is https on an ssl listener', 'GET https://localhost:18156/request/scheme') do
  t.assert_equal 'https|https', `curl -s -k #{base_ssl(18156)}/request/scheme`
end

t.assert('Nginx::Request#document_root is the root of the location, as Nginx::Server#document_root and $document_root', 'GET /request/document_root on 18155') do
  res = HttpRequest.new.get base(18155) + '/request/document_root'
  t.assert_equal 200, res.code
  request_root, server_root, var_root = res["body"].split("|")
  t.assert_equal File.join(ENV['NGINX_INSTALL_DIR'], 'html', 'request_document_root'), request_root
  t.assert_equal request_root, server_root
  t.assert_equal request_root, var_root
end

t.assert('Nginx::SSL.log writes its message to error.log in the handshake handler', 'handshake on 18156') do
  offset = File.size(module_and_request_log_path)
  t.assert_equal 'https|https', `curl -s -k #{base_ssl(18156)}/request/scheme`
  lines = module_and_request_log_lines(offset).select { |l| l.include?('Nginx::SSL.log in handshake: ') }
  t.assert_equal 1, lines.size
  t.assert_include lines[0].to_s, '[notice]'
  t.assert_include lines[0].to_s, 'Nginx::SSL.log in handshake: servername=localhost 42'
end

t.report
