# The key of limit_req for the request (test/conf/conf.d/75-guide-rate-limit.conf):
# the API key of the request, or the client address when it has none.
r = Nginx::Request.new
key = r.headers_in["X-API-Key"].to_s
key.empty? ? "addr:#{r.var.remote_addr}" : "key:#{key}"
