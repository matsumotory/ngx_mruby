# How nginx sends a static file in a location with an mruby output filter.
# ngx_mruby asks nginx for the body in memory (r->filter_need_in_memory)
# where the body filter reads it, and nginx's copy filter then reads the file
# into memory before the filters get it. A location with a header filter
# alone reads no body, so nginx passes the file on unread and sends it with
# sendfile.
#
# The response is the same either way, so the case reads nginx's debug log:
# the second nginx (test/t/cases/_second_instance.rb, mode http_sendfile,
# port 18116) has sendfile on, a header filter in its server block, which
# both locations inherit, and an error log of its own at the debug level.
# For each request, it counts the lines "read: " of nginx's reads of a file
# into memory and the lines "sendfile: @" of nginx's sendfile calls.
# second_instance is in test/t/cases/_prelude.rb.

t = SimpleTest.new "ngx_mruby test: static files with output filters"

t.assert('filter sendfile', 'the second nginx: a static file with a header filter alone, and with a body filter') do
  r = second_instance('http_sendfile')
  if r['error'] || r['sanitizer']
    puts File.read(File.join(ENV['NGINX_INSTALL_DIR'], 'second_instance', 'http_sendfile', 'error.log'))
  end
  t.assert_nil r['error']
  t.assert_nil r['sanitizer']
  # The header filter ran and the body is the file. nginx did not read the
  # file into memory, and sent it with sendfile: at least one line
  # "sendfile: @".
  status, header, body, reads, sendfile_lines = r['header_only'].to_s.split('|', 5)
  t.assert_equal 'HTTP/1.1 200 OK', status
  t.assert_equal 'ran', header
  t.assert_equal 'sendfile body', body
  t.assert_equal '0', reads
  t.assert_true sendfile_lines.to_i > 0, "sendfile lines for /header/: #{sendfile_lines.inspect}"
  # The body filter got the file in memory: one read of the file of 14
  # bytes, and no line "sendfile: @", because the filter sends the body
  # that it made.
  t.assert_equal 'HTTP/1.1 200 OK|ran|SENDFILE BODY|1|0', r['with_body']
  t.assert_equal 'exited 0', r['exit']
end

t.report
