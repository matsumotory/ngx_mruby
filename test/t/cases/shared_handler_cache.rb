# A file-based mruby content handler is shared by two locations via a
# server-level mruby_content_handler with no cache keyword: /off (mruby_cache
# off, the default) recompiles the shared code on every request, and /on
# (mruby_cache on) reuses the compiled proc. This alternates /off and /on and
# checks that /on keeps answering with the handler's output. The suite runs
# with -DMRB_GC_STRESS.
# Config: test/conf/conf.d/99-shared-handler-cache.conf (port 18121).

t = SimpleTest.new "ngx_mruby test: a shared file content handler recompiled by an mruby_cache off location stays valid for an mruby_cache on location"

SHARED_HANDLER_CACHE_PORT = 18121

def shared_handler_get(path)
  req = "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n"
  status, raw = tcp_client(SHARED_HANDLER_CACHE_PORT, req)
  _, body = raw.to_s.split("\r\n\r\n", 2)
  [status, body.to_s]
end

t.assert('shared handler cache', '/on answers after /off recompiled the shared code') do
  3.times do
    off_status, off_body = shared_handler_get('/off')
    t.assert_equal 'EOF', off_status
    t.assert_equal 'shared handler', off_body
    on_status, on_body = shared_handler_get('/on')
    t.assert_equal 'EOF', on_status
    t.assert_equal 'shared handler', on_body
  end
end

t.report
