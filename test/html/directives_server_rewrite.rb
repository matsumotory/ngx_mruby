# Server rewrite phase hook, file version. Loaded by
# mruby_server_rewrite_handler in test/conf/conf.d/30-directives.conf.
# It returns DECLINED so that nginx continues to the next phase.
r = Nginx::Request.new
r.headers_in["X-G3-Trace"] = "#{r.headers_in["X-G3-Trace"]},server_rewrite"
Nginx.return Nginx::DECLINED
