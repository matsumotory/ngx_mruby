#!/usr/bin/env ruby
# Raw socket client for test/t/cases/filter_connection.rb. It runs under
# CRuby because the test build of mruby has no plain TCP socket with access
# to the local port. It connects only to 127.0.0.1.
#
# Modes:
#   remote_port   GET /g2fc/conn/remote_port on 58112 and print
#                 "<client local port>|<response body>"
#   filter_empty  GET /g2fc/filter/output_empty on 58112 and print the status
#                 line, or "<closed>" when no byte comes back
#   pp_v1_tcp4    PROXY protocol v1 line with TCP4 addresses to 58113
#   pp_v1_tcp6    PROXY protocol v1 line with TCP6 addresses to 58113
#   pp_v1_unknown PROXY protocol v1 line "PROXY UNKNOWN" to 58113
#   pp_v2_tcp4    PROXY protocol v2 binary header with TCP4 addresses to 58113
#   pp_none       no PROXY header to 58113
# The pp_* modes print the response body, or "<closed>" when nginx closes
# the connection without a response.

require 'socket'

def request(path)
  "GET #{path} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
end

def body_of(raw)
  return '<closed>' if raw.nil? || raw.empty?
  raw.split("\r\n\r\n", 2)[1].to_s
end

def send_raw(port, prefix, path)
  Socket.tcp('127.0.0.1', port, connect_timeout: 5) do |s|
    s.write prefix
    s.write request(path)
    port = s.local_address.ip_port
    s.close_write
    raw = begin
      s.read
    rescue Errno::ECONNRESET
      nil
    end
    [port, raw]
  end
end

def pp_v2_tcp4
  sig = "\r\n\r\n\x00\r\nQUIT\n".b
  ver_cmd = [0x21].pack('C')        # version 2, command PROXY
  fam = [0x11].pack('C')            # AF_INET, STREAM
  addrs = [192, 0, 2, 30].pack('C4') + [192, 0, 2, 40].pack('C4') + [40002, 9443].pack('nn')
  sig + ver_cmd + fam + [addrs.bytesize].pack('n') + addrs
end

mode = ARGV[0]
case mode
when 'remote_port'
  port, raw = send_raw(58112, '', '/g2fc/conn/remote_port')
  puts "#{port}|#{body_of(raw)}"
when 'filter_empty'
  _, raw = send_raw(58112, '', '/g2fc/filter/output_empty')
  puts(raw.nil? || raw.empty? ? '<closed>' : raw.split("\r\n").first)
when 'pp_v1_tcp4'
  _, raw = send_raw(58113, "PROXY TCP4 192.0.2.10 192.0.2.20 40000 8443\r\n", '/g2fc/pp')
  puts body_of(raw)
when 'pp_v1_tcp6'
  _, raw = send_raw(58113, "PROXY TCP6 2001:db8::1 2001:db8::2 40001 443\r\n", '/g2fc/pp')
  puts body_of(raw)
when 'pp_v1_unknown'
  _, raw = send_raw(58113, "PROXY UNKNOWN\r\n", '/g2fc/pp')
  puts body_of(raw)
when 'pp_v2_tcp4'
  _, raw = send_raw(58113, pp_v2_tcp4, '/g2fc/pp')
  puts body_of(raw)
when 'pp_none'
  _, raw = send_raw(58113, '', '/g2fc/pp')
  puts body_of(raw)
else
  warn "unknown mode: #{mode}"
  exit 1
end
