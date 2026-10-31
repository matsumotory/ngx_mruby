# A second UDP datagram of the same stream session starts a second fiber while
# the first is still suspended in Nginx::Stream::Async.sleep. The second fiber
# must be kept from the GC while it sleeps; otherwise the test build (which runs
# the GC on every allocation) collects it, its resume raises a FiberError, the
# session is aborted and the UDP client gets no reply. The fix registers each
# fiber of a session with the GC on its own, not once per session. Config:
# test/conf/conf.d/stream/46-async-sleep-udp-reuse.conf (ports 12390, 12391).
# _udp_reuse.rb is in this directory and runs with CRuby.

t = SimpleTest.new "ngx_mruby test: a second UDP datagram's stream fiber is kept from the GC through Async.sleep"

t.assert('ngx_mruby - stream Async.sleep UDP reuse: the second datagram resumes and answers', 'the reply is the return body, the session is not aborted') do
  reply = `ruby #{suite_path('test/t/cases/_udp_reuse.rb')} 12390 12391`
  t.assert_include reply, 'udp-reuse-ok'
end

t.report
