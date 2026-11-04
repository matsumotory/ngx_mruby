# The same UDP session receives another datagram while its code waits.
# Allocations in the shared stream VM must not collect the waiting fiber.
# Config: test/conf/conf.d/stream/46-async-sleep-udp-reuse.conf.
# _udp_reuse.rb runs with CRuby; ports 12390 and 12391.

t = SimpleTest.new "ngx_mruby test: the waiting UDP stream fiber stays registered through Async.sleep"

t.assert('ngx_mruby - stream Async.sleep UDP reuse: the waiting code resumes and answers', 'the reply is the return body, the session is not aborted') do
  reply = `ruby #{suite_path('test/t/cases/_udp_reuse.rb')} 12390 12391`
  t.assert_include reply, 'udp-reuse-ok'
end

t.report
