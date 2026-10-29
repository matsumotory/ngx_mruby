#!/usr/bin/env ruby
# Connects to 127.0.0.1:PORT, waits PRECLOSE seconds so the stream session
# code has run and armed its Nginx::Stream::Async.sleep timer, then resets the
# connection (SO_LINGER 0, so close() sends a RST) so nginx ends the session
# while the timer is still pending. It then waits POSTWAIT seconds, long enough
# for that timer to fire, before it returns, so that a use-after-free the timer
# causes happens while the case is still running. Runs with CRuby, like the
# other helpers in this directory.
#
# Usage: ruby test/t/cases/_tcp_abort.rb PORT [PRECLOSE_SECONDS] [POSTWAIT_SECONDS]
# It prints "aborted" when it has reset the connection and waited.

require 'socket'

port = Integer(ARGV[0])
preclose = Float(ARGV[1] || '1.0')
postwait = Float(ARGV[2] || '0.0')

sock = Socket.tcp('127.0.0.1', port, connect_timeout: 5)
sleep preclose
# SO_LINGER {on, 0}: close() sends a RST, so nginx ends the session at once.
sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack('ii'))
sock.close
sleep postwait
print 'aborted'
