# The instance methods of Nginx::Stream::Connection that read the addresses
# and ports of the session, the class method local_addr, the getter
# upstream_server, Nginx::Stream.errlogger and Nginx::Stream.module_name.
# Config: test/conf/conf.d/stream/41-stream-connection.conf (port 12363).
# tcp_client is in test/t/cases/_prelude.rb.

t = SimpleTest.new "ngx_mruby test: stream connection (port 12363)"

def stream_connection_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

def stream_connection_log_lines(offset)
  File.open(stream_connection_log_path) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
end

t.assert('ngx_mruby - stream Connection instance methods, class local_addr, upstream_server, errlogger and module_name', '127.0.0.1:12363') do
  offset = File.size(stream_connection_log_path)
  status, reply = tcp_client(12363)
  t.assert_equal 'EOF', status
  remote_addr, remote_port, server_addr, server_port = reply.split(' ')
  t.assert_equal '127.0.0.1', remote_addr
  t.assert_equal '127.0.0.1', server_addr
  t.assert_equal '12363', server_port

  # The line of the session holds the values; the dump of the session code
  # holds "#{" instead.
  lines = stream_connection_log_lines(offset).select { |l| l.include?('stream connection case: remote_ip=') && !l.include?('#{') }
  t.assert_equal 1, lines.size
  t.assert_include lines[0].to_s, '[notice]'
  values = {}
  lines[0].to_s.split('stream connection case: ', 2)[1].to_s.split(' end')[0].to_s.split(' ').each do |pair|
    key, value = pair.split('=', 2)
    values[key] = value
  end

  # The client and the server are both 127.0.0.1, so the addresses do not
  # tell the methods of the peer from those of the local side; the ports
  # do (12363 against the port of the client).
  t.assert_equal remote_addr, values['remote_ip']
  t.assert_equal remote_addr, values['remote_addr']
  t.assert_equal remote_port, values['remote_port']
  t.assert_equal server_addr, values['local_ip']
  t.assert_equal server_addr, values['local_addr']
  t.assert_equal server_port, values['local_port']
  t.assert_equal "#{server_addr}:#{server_port}", values['local_ip_port']
  %w[remote_ip remote_addr remote_port local_ip local_addr local_port local_ip_port].each do |name|
    t.assert_equal values[name], values["class_#{name}"]
  end
  t.assert_equal '127.0.0.1:12358', values['upstream_server']
  t.assert_equal 'ngx_mruby-stream-module', values['module_name']
end

t.report
