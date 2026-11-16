# Whether nginx sends a static file with sendfile in a location with an mruby
# output filter. ngx_mruby asks nginx for the body in memory
# (r->filter_need_in_memory) where the body filter reads it, and nginx then
# reads a file into memory instead of sending it with sendfile. A location
# with a header filter alone reads no body, and keeps sendfile.
#
# The response is the same either way, so the case reads nginx's debug log:
# the second nginx (test/t/cases/_second_instance.rb, mode http_sendfile,
# port 18116) has sendfile on, a header filter in its server block, which
# both locations inherit, and an error log of its own at the debug level.
# second_instance is in test/t/cases/_prelude.rb.

t = SimpleTest.new "ngx_mruby test: sendfile with output filters"

t.assert('filter sendfile', 'the second nginx: a static file with a header filter alone, and with a body filter') do
  r = second_instance('http_sendfile')
  if r['error'] || r['sanitizer']
    puts File.read(File.join(ENV['NGINX_INSTALL_DIR'], 'second_instance', 'http_sendfile', 'error.log'))
  end
  t.assert_nil r['error']
  t.assert_nil r['sanitizer']
  # The header filter ran, the body is the file, and nginx sent the file with
  # sendfile: at least one line "sendfile: @" for the request.
  status, header, body, sendfile_lines = r['header_only'].to_s.split('|', 4)
  t.assert_equal 'HTTP/1.1 200 OK', status
  t.assert_equal 'ran', header
  t.assert_equal 'sendfile body', body
  t.assert_true sendfile_lines.to_i > 0, "sendfile lines for /header/: #{sendfile_lines.inspect}"
  # The body filter read the file from memory: no line "sendfile: @".
  t.assert_equal 'HTTP/1.1 200 OK|ran|SENDFILE BODY|0', r['with_body']
  t.assert_equal 'exited 0', r['exit']
end

t.report
