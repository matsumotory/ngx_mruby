# The content handler of the home page example (test/conf/conf.d/70-home-example.conf).
r = Nginx::Request.new
name = r.var.arg_name.to_s
name = "world" if name.empty?
r.content_type = "text/plain"
r.headers_out["X-Greeting-For"] = name
Nginx.rputs "Hello, #{name}! nginx ran this Ruby script for #{r.method} #{r.uri}.\n"
