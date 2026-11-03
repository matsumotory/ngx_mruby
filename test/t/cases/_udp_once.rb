# Finite same-source UDP exchange, run by CRuby.
require 'socket'
port, count = ARGV.map { |arg| Integer(arg) }
raise ArgumentError unless (1..10).include?(count)
u = UDPSocket.new
begin
  u.connect('127.0.0.1', port)
  count.times do |i|
    u.send("datagram #{i}", 0)
    sleep 0.05 if i + 1 < count
  end
  print(IO.select([u], nil, nil, 3.0) ? u.recv(100) : 'noreply')
ensure
  u.close
end
