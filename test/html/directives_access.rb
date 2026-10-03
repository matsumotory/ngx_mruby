# Access phase hook, file version. Loaded by mruby_access_handler in
# test/conf/conf.d/30-directives.conf. A query string that contains
# deny=1 makes the hook reject the request with 403.
r = Nginx::Request.new
if r.args.to_s.include?("deny=1")
  Nginx.return Nginx::HTTP_FORBIDDEN
else
  r.headers_in["X-G3-Trace"] = "#{r.headers_in["X-G3-Trace"]},access"
end
