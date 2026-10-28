# Nginx::Stream::Connection#upstream_server= keeps the round-robin peer valid
# for a later connection. Config: test/conf/conf.d/stream/42-upstream-server.conf
# (ports 12360, 12361). A connection to 12360 sets the server to
# 127.0.0.1:12364 (the upstream block names 127.0.0.1:12362); a later
# connection to 12361 reads it back and logs GOTSERVER. The peer is shared and
# lives for the worker's life, so the address that the first connection stored
# must still be readable in the second. tcp_client is in
# test/t/cases/_prelude.rb.

t = SimpleTest.new "ngx_mruby test: Nginx::Stream::Connection#upstream_server= across connections"

def stream_upstream_server_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

def stream_upstream_server_log_lines(offset)
  File.open(stream_upstream_server_log_path) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
end

t.assert('ngx_mruby - stream upstream_server= then read it in a later connection', '12360 then 12361') do
  offset = File.size(stream_upstream_server_log_path)
  set_status, = tcp_client(12360)
  t.assert_equal 'EOF', set_status
  get_status, = tcp_client(12361)
  t.assert_equal 'EOF', get_status

  lines = stream_upstream_server_log_lines(offset).select { |l| l.include?('stream upstream server test: GOTSERVER=') }
  t.assert_equal 1, lines.size
  t.assert_include lines[0].to_s, '[notice]'
  t.assert_include lines[0].to_s, 'GOTSERVER=127.0.0.1:12364 end'
end

t.report
