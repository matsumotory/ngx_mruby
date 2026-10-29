#!/usr/bin/env ruby
# A Redis client for test/t/cases/auto_ssl.rb, which runs it with CRuby: the
# test build of mruby has no Redis client, and the case checks what the
# auto-ssl handlers wrote with a client of its own, not with the
# mruby-redis of the nginx under test. It speaks RESP to 127.0.0.1:6379,
# the Redis of test/auto_ssl/deps.sh.
#
# Usage: ruby test/t/cases/_redis_client.rb get KEY
#        ruby test/t/cases/_redis_client.rb set KEY HEX
#        ruby test/t/cases/_redis_client.rb del KEY...
#
# get prints "nil" for a missing key, or "value:" and the value in hex; set
# takes the value in hex and prints "OK"; del prints the number of keys that
# it removed. Any other reply, or no connection, prints "error:" and the
# reason, and the exit status is 1.

require 'socket'

def command(sock, args)
  sock.write("*#{args.size}\r\n" + args.map { |a| "$#{a.bytesize}\r\n#{a}\r\n" }.join)
  line = sock.gets("\r\n")
  raise 'no reply' unless line
  case line[0]
  when '+' then line[1..-3]
  when ':' then Integer(line[1..-3], 10)
  when '-' then raise "Redis: #{line[1..-3]}"
  when '$'
    len = Integer(line[1..-3], 10)
    return nil if len < 0
    data = sock.read(len + 2)
    raise 'short reply' unless data && data.bytesize == len + 2
    data[0, len]
  else
    raise "unexpected reply #{line.inspect}"
  end
end

begin
  op = ARGV.shift
  sock = Socket.tcp('127.0.0.1', 6379, connect_timeout: 5)
  case op
  when 'get'
    v = command(sock, ['GET', ARGV.fetch(0)])
    puts(v.nil? ? 'nil' : "value:#{v.unpack1('H*')}")
  when 'set'
    puts command(sock, ['SET', ARGV.fetch(0), [ARGV.fetch(1)].pack('H*')])
  when 'del'
    raise 'del needs a key' if ARGV.empty?
    puts command(sock, ['DEL', *ARGV])
  else
    raise "unknown command #{op.inspect}"
  end
rescue StandardError => e
  puts "error:#{e.class}: #{e.message}"
  exit 1
end
