# The stream handler of test/conf/conf.d/stream/42-guide-tcp.conf: lets the
# TCP session through to proxy_pass only from the addresses of the list,
# and closes the others.
allowed = ["127.0.0.1", "::1"]
c = Nginx::Stream::Connection
c.stream_status = Nginx::Stream::ABORT unless allowed.include?(c.remote_ip)
