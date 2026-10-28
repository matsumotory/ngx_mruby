# The content handler of the start page (examples/start/nginx.conf).
r = Nginx::Request.new
name = r.var.arg_name.to_s
name = "world" if name.empty?
r.content_type = "text/plain"
Nginx.rputs "Hello, #{name}! hello.rb answered #{r.method} #{r.uri}.\n"
