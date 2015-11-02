c = Nginx::Stream::Connection.new "dynamic_server1"
c.upstream_server = "127.0.0.1:58080"
