# A handler file without cache is compiled again on each request, and the
# new proc replaces the previous one in the slot of the code in the GC root
# holder (section 2.6 of docs/proposals/core-alpha1.md).
# Config: test/conf/conf.d/98-code-reload.conf (port 18125).
# Hook script: test/html/code_reload_sleep.rb.

t = SimpleTest.new "ngx_mruby test: code without cache"

def code_reload_stats
  res = HttpRequest.new.get base(18125) + '/code_reload/stats'
  [res.code, res["body"]]
end

# Sends two requests to /code_reload/sleep, the second 0.2 seconds after the
# first, so that the second compiles the code again while the first waits in
# Nginx::Async.sleep. Each client prints "STATUS:HEX" (_tcp_client.rb); the
# first one prints into a file, which is read after the second. Returns the
# [status, response] of the second request and of the first.
def code_reload_overlapping
  client = "ruby #{suite_path('test/t/cases/_tcp_client.rb')} 18125"
  first = File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'code_reload_first.out')
  hex = "GET /code_reload/sleep HTTP/1.0\r\nHost: localhost\r\n\r\n".unpack("H*")[0]
  out = `#{client} #{hex} > #{first} & sleep 0.2; #{client} #{hex}; wait; echo; cat #{first}`
  out.split("\n").map do |line|
    status, h = line.split(":", 2)
    [status, [h.to_s].pack("H*")]
  end
end

t.assert('code without cache', 'a request that waits keeps its proc while another request compiles the code again') do
  before = code_reload_stats
  results = code_reload_overlapping
  after = code_reload_stats

  t.assert_equal 2, results.size
  bodies = results.map do |status, raw|
    t.assert_equal 'EOF', status
    head, body = raw.split("\r\n\r\n", 2)
    t.assert_equal 'HTTP/1.1 200 OK', head.to_s.split("\r\n")[0]
    body
  end
  # The second request started while the first waited.
  t.assert_equal ['reloaded:2,4,6;waiting=2', 'reloaded:2,4,6;waiting=1'], bodies

  # The compile of each request put its proc in the same slot: the number of
  # objects kept from the GC is the same as before.
  t.assert_equal 200, before[0]
  t.assert_equal 200, after[0]
  t.assert_equal true, before[1].start_with?('gc_root=')
  t.assert_equal before[1], after[1]
end

t.assert('code without cache', 'the code of mruby_add_handler, made for one request, keeps no slot') do
  before = code_reload_stats
  res = HttpRequest.new.get base + '/add_handler.rb'
  after = code_reload_stats

  t.assert_equal 'add_handler', res["body"]
  t.assert_equal before[1], after[1]
end

t.report
