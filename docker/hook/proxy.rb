# location /proxy {
#   mruby_set $backend "/path/to/proxy.rb";
#   proxy_pass   http://$backend;
# }

backends = [
  "127.0.0.1:80",
]

unless ENV["PROXY1_PORT_80_TCP_ADDR"].nil?
  backends << ENV["PROXY1_PORT_80_TCP_ADDR"] + ":" + ENV["PROXY1_PORT_80_TCP_PORT"]
end

unless ENV["PROXY2_PORT_80_TCP_ADDR"].nil?
  backends << ENV["PROXY2_PORT_80_TCP_ADDR"] + ":" + ENV["PROXY2_PORT_80_TCP_PORT"]
end

unless ENV["PROXY3_PORT_80_TCP_ADDR"].nil?
  backends << ENV["PROXY3_PORT_80_TCP_ADDR"] + ":" + ENV["PROXY3_PORT_80_TCP_PORT"]
end

uri = '/mruby-hello'

backends[rand(backends.length)] + uri
