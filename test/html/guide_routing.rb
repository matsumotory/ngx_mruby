# The backend of the request, for proxy_pass (test/conf/conf.d/73-guide-routing.conf).
# The value of the last line is the value of $backend.
backends = {
  "a" => "127.0.0.1:18164",
  "b" => "127.0.0.1:18165",
}
tenant = Nginx::Request.new.headers_in["X-Tenant"].to_s
backends.fetch(tenant, backends["a"])
