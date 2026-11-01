#!/usr/bin/env ruby
# Sends COUNT UDP datagrams from one source to UDP_PORT, 50 ms apart, while
# the stream code of that port sleeps, and prints the reply, or "noreply"
# when none arrives within 3 seconds. nginx gives every datagram of the
# source to the same session (ngx_lookup_udp_connection). Runs with CRuby,
# like the other helpers in this directory.
#
# Usage: ruby test/t/cases/_udp_once.rb UDP_PORT COUNT
require 'socket'

udp_port = Integer(ARGV[0])
count = Integer(ARGV[1])

u = UDPSocket.new
u.connect('127.0.0.1', udp_port)
count.times do |i|
  u.send("datagram #{i}", 0)
  sleep 0.05
end

ready = IO.select([u], nil, nil, 3.0)
print(ready ? u.recv(100) : 'noreply')
