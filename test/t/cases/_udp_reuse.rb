#!/usr/bin/env ruby
# Sends two UDP datagrams from one source to UDP_PORT, whose stream handler
# sleeps in Nginx::Stream::Async.sleep. nginx reuses the session for the second
# datagram (ngx_lookup_udp_connection), so it re-runs the handler and starts a
# second fiber while the first still sleeps. During the sleep this connects to
# ALLOC_PORT several times; that server's code allocates, and the test build
# runs the GC on every allocation, so a second fiber that is not kept from the
# GC is collected and its resume fails. It then reads the UDP reply (the
# handler's `return` body, sent after the sleep) and prints it, or "noreply" if
# none arrives before the timeout. Runs with CRuby, like the other helpers in
# this directory.
#
# Usage: ruby test/t/cases/_udp_reuse.rb UDP_PORT ALLOC_PORT
require 'socket'

udp_port = Integer(ARGV[0])
alloc_port = Integer(ARGV[1])

u = UDPSocket.new
u.connect('127.0.0.1', udp_port)
u.send('one', 0)
sleep 0.3           # let the first fiber arm its sleep timer
u.send('two', 0)    # reuse the session: a second fiber starts and sleeps

# Run the GC in the shared stream mrb_state while the second fiber sleeps, so a
# fiber that is not a GC root is collected before its timer resumes it.
deadline = Time.now + 1.0
while Time.now < deadline
  begin
    t = Socket.tcp('127.0.0.1', alloc_port, connect_timeout: 2)
    t.read
    t.close
  rescue StandardError
    # ignore; keep allocating until the deadline
  end
end

ready = IO.select([u], nil, nil, 2.0)
print(ready ? u.recv(100) : 'noreply')
