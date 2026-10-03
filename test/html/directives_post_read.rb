# Post-read phase hook, file version. Loaded by mruby_post_read_handler in
# test/conf/conf.d/30-directives.conf (server on port 18114). It starts the
# X-Phase-Trace request header that the later phases extend.
r = Nginx::Request.new
r.headers_in["X-Phase-Trace"] = "post_read"
