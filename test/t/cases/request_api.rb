t = SimpleTest.new "ngx_mruby test: request API (test/conf/conf.d/10-request-api.conf)"

REQUEST_API_PORT = 18111

t.assert('request API', 'rewrite handler without output or DECLINED sends no response') do
  # characterizes v2 behaviour; see docs/proposals/v3-plan.md on the next branch
  # The handler returns NGX_OK to the rewrite phase, so nginx finalizes the
  # request with rc 0 and closes the connection without writing a byte.
  # tcp_client in test/t/cases/_prelude.rb reads until nginx closes the
  # connection and stops waiting after a time limit.
  res = tcp_client(REQUEST_API_PORT, "GET /request_api/rewrite_no_return HTTP/1.0\r\n\r\n")
  t.assert_equal ["EOF", ""], res
end

t.assert('request API', 'getters on /request_api/getters/') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/getters/a%20b?q=1'
  t.assert_equal 200, res.code
  t.assert_equal 'GET /request_api/getters/a%20b?q=1 HTTP/1.0|/request_api/getters/a%20b?q=1|/request_api/getters/a b|q=1|HTTP/1.0', res["body"]
end

t.assert('request API', 'uri= in rewrite phase is seen by $uri, not by $request_uri') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/uri_set?x=1'
  t.assert_equal 200, res.code
  t.assert_equal '/request_api/uri_changed|/request_api/uri_changed|/request_api/uri_set?x=1|/request_api/uri_set?x=1', res["body"]
end

t.assert('request API', 'uri= with nil keeps the URI') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/uri_nil'
  t.assert_equal '/request_api/uri_nil', res["body"]
end

t.assert('request API', 'filename is the document root joined with the URI') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/filename'
  filename, docroot = res["body"].split("|")
  t.assert_equal docroot + '/request_api/filename', filename
  t.assert_true filename.end_with?('/nginx/html/request_api/filename')
end

t.assert('request API', 'filename follows uri= set in rewrite phase') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/filename_after_uri'
  filename, docroot = res["body"].split("|")
  t.assert_equal docroot + '/request_api/other.txt', filename
end

t.assert('request API', 'uri= reaches proxy_pass with a URI part') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/proxy_uri/original?x=1'
  t.assert_equal 200, res.code
  t.assert_equal 'GET /echo/rewritten?x=1 HTTP/1.1', res["body"]
end

t.assert('request API', 'uri= does not reach proxy_pass without a URI part') do
  # characterizes v2 behaviour; see docs/proposals/v3-plan.md on the next branch
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/proxy_uri_raw/original?z=3'
  t.assert_equal 200, res.code
  t.assert_equal 'GET /request_api/proxy_uri_raw/original?z=3 HTTP/1.1', res["body"]
end

t.assert('request API', 'unparsed_uri= reaches proxy_pass without a URI part') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/proxy_unparsed/original?y=1'
  t.assert_equal 200, res.code
  t.assert_equal 'GET /from/unparsed?y=2 HTTP/1.1', res["body"]
end

t.assert('request API', 'unparsed_uri= is seen by the getter and $request_uri') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/unparsed_set?a=1'
  t.assert_equal '/replaced?z=9|/replaced?z=9|/request_api/unparsed_set', res["body"]
end

t.assert('request API', 'args= in rewrite phase is seen by $args and $arg_name') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/args_set?old=1'
  t.assert_equal 'k=v&n=2|k=v&n=2|v|2|nil', res["body"]
end

t.assert('request API', 'args= reaches proxy_pass with a URI part') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/proxy_args/p?old=1'
  t.assert_equal 'GET /echo/p?k=v HTTP/1.1', res["body"]
end

t.assert('request API', 'request_line= changes the getter and $request') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/request_line_set?a=1'
  t.assert_equal 'GET /request_api/request_line_set?a=1 HTTP/1.0|BREW /pot HTCPCP/1.0|BREW /pot HTCPCP/1.0', res["body"]
end

t.assert('request API', 'protocol= changes the getter and $server_protocol') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/protocol_set'
  t.assert_equal 'HTTP/1.0|HTTP/9.9|HTTP/9.9', res["body"]
end

t.assert('request API', 'user reads the Basic auth user') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/user', nil, {"Authorization" => "Basic YXBpdXNlcjpzZWNyZXQ="}
  t.assert_equal 'user="apiuser"', res["body"]
end

t.assert('request API', 'user is nil without Authorization') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/user'
  t.assert_equal 'user=nil', res["body"]
end

t.assert('request API', 'Headers_in#user_agent returns the User-Agent value') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/ua', nil, {"User-Agent" => "request-api-agent/1.0"}
  t.assert_equal 'ua="request-api-agent/1.0"', res["body"]
end

t.assert('request API', 'Headers_in#user_agent is nil without User-Agent') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/ua'
  t.assert_equal 'ua=nil', res["body"]
end

t.assert('request API', 'send_header 200 after rputs sends the body') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/send_header/body_200'
  t.assert_equal 200, res.code
  t.assert_equal 'body-ok', res["body"]
end

t.assert('request API', 'send_header 200 without a body becomes 500') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/send_header/empty_200'
  t.assert_equal 500, res.code
  t.assert_include res["body"], '<title>500 Internal Server Error</title>'
end

t.assert('request API', 'send_header 404 without a body sends the nginx error page') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/send_header/empty_404'
  t.assert_equal 404, res.code
  t.assert_true res["body"].include?('<title>404 Not Found</title>')
end

t.assert('request API', 'send_header 404 after rputs replaces the body with the nginx error page') do
  # characterizes v2 behaviour; see docs/proposals/v3-plan.md on the next branch
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/send_header/body_404'
  t.assert_equal 404, res.code
  t.assert_true res["body"].include?('<title>404 Not Found</title>')
  t.assert_equal false, res["body"].include?('custom-body')
end

t.assert('request API', 'send_header 201 after rputs drops the body') do
  # characterizes v2 behaviour; see docs/proposals/v3-plan.md on the next branch
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/send_header/body_201'
  t.assert_equal 201, res.code
  t.assert_equal '', res["body"]
end

t.assert('request API', 'Nginx.return is send_header') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/send_header/return_403'
  t.assert_equal 403, res.code
  t.assert_true res["body"].include?('<title>403 Forbidden</title>')
end

t.assert('request API', 'Nginx.status_code= is send_header') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/send_header/status_code_body'
  t.assert_equal 200, res.code
  t.assert_equal 'status-body', res["body"]
end

t.assert('request API', 'Server#realpath_root resolves .. in root') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/realpath'
  docroot, realpath, path = res["body"].split("|")
  t.assert_true docroot.end_with?('/nginx/html/image/..')
  t.assert_equal docroot[0, docroot.size - '/image/..'.size], realpath
  t.assert_equal realpath, path
end

t.assert('request API', 'Nginx.configure is the configure arguments of nginx -V') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/configure'
  conf = res["body"]
  # NGX_CONFIGURE starts with a space; nginx -V prints it right after the colon.
  t.assert_true conf.start_with?(' --')
  t.assert_true conf.include?('--add-')
  out = `#{ENV['NGINX_INSTALL_DIR']}/sbin/nginx -V 2>&1`
  t.assert_include out, "configure arguments:#{conf}\n"
end

t.assert('request API', 'remove_global_variable with a Symbol and a String') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/gv/remove'
  t.assert_equal 'true|Array|false|true|false|nil|nil', res["body"]
end

t.assert('request API', 'global variables persist between requests until removed') do
  t.assert_equal 'set', HttpRequest.new.get(base(REQUEST_API_PORT) + '/request_api/gv/set')["body"]
  t.assert_equal '"kept"', HttpRequest.new.get(base(REQUEST_API_PORT) + '/request_api/gv/get')["body"]
  t.assert_equal 'false', HttpRequest.new.get(base(REQUEST_API_PORT) + '/request_api/gv/drop')["body"]
  t.assert_equal 'nil', HttpRequest.new.get(base(REQUEST_API_PORT) + '/request_api/gv/get')["body"]
end

t.assert('request API', 'Nginx::TRUE and Nginx::FALSE are "1" and "0"') do
  res = HttpRequest.new.get base(REQUEST_API_PORT) + '/request_api/flag/values'
  t.assert_equal '"1"|"0"|String', res["body"]
end

t.assert('request API', 'Nginx::TRUE and Nginx::FALSE drive the rewrite module if') do
  t.assert_equal 'flag-on', HttpRequest.new.get(base(REQUEST_API_PORT) + '/request_api/flag/true')["body"]
  t.assert_equal 'flag-off', HttpRequest.new.get(base(REQUEST_API_PORT) + '/request_api/flag/false')["body"]
end

t.report
