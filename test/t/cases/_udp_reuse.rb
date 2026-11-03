#!/usr/bin/env ruby
# Send two datagrams to one waiting UDP session, allocate through the TCP
# server, and read the reply after the waiting code resumes.
# Usage: ruby test/t/cases/_udp_reuse.rb UDP_PORT ALLOC_PORT
require 'socket'

udp_port = Integer(ARGV[0])
alloc_port = Integer(ARGV[1])

u = UDPSocket.new
u.connect('127.0.0.1', udp_port)
u.send('one', 0)
sleep 0.3           # let the first fiber arm its sleep timer
u.send('two', 0)    # reuse the same waiting session

# Run the GC in the shared stream mrb_state while the session code sleeps, so a
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
