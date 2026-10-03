# Handler of the "file" scenario of the memory soak test
# (mruby_content_handler with the cache option, see test/soak/nginx.conf).
r = Nginx::Request.new
Nginx.rputs "file:#{r.uri}"
