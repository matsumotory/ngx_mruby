#!/usr/bin/env ruby

require 'socket'

request_body = %({"hello": "ngx_mruby"})
headers = <<HEAD.gsub("\n", "\r\n")
POST /issue-268 HTTP/1.0
Content-Type: application/json
User-Agent: issue-268-test
Content-Length: #{request_body.length}
HEAD

Socket.tcp("localhost", 58080) do |s|
  s.print headers
  s.print "\r\n"
  sleep 0.3 # <==== important!
  s.print request_body
  s.close_write
  puts s.read
end
