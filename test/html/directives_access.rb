# Access phase hook, file version. Loaded by mruby_access_handler in
# test/conf/conf.d/30-directives.conf. A query string that contains deny=1
# makes the hook store the trace it saw and reject the request with 403. A
# later request to /directives/denied_trace reads the stored trace.
r = Nginx::Request.new
if r.args.to_s.include?("deny=1")
  Userdata.new.denied_trace = r.headers_in["X-Phase-Trace"].to_s
  Nginx.return Nginx::HTTP_FORBIDDEN
else
  r.headers_in["X-Phase-Trace"] = "#{r.headers_in["X-Phase-Trace"]},access"
end
