# An independent nginx checks repeated waits, UDP proxy payloads and shutdown.
# _udp_wait_session.rb uses CRuby and finite exchanges on ports 12393-12396.
t = SimpleTest.new 'ngx_mruby test: waiting UDP session lifecycle'
result = JSON.parse(`ruby test/t/cases/_udp_wait_session.rb`)
t.assert('stream', 'two successive sleeps resume the same handler') do
  t.assert_equal nil, result['error']
  t.assert_equal 'repeat-ok', result['repeat_reply']
  t.assert_equal [1, 1, 1], result['repeat_counts']
end
t.assert('stream', 'UDP proxy forwards the first and later payload exactly') do
  t.assert_equal nil, result['error']
  t.assert_equal '6563686f3a666972737400ff7061796c6f6164', result['proxy_first_reply']
  t.assert_equal '6563686f3a6c6174657200fe7061796c6f6164', result['proxy_later_reply']
  t.assert_equal ['666972737400ff7061796c6f6164', '6c6174657200fe7061796c6f6164'], result['proxy_upstream_payloads']
  t.assert_equal 1, result['proxy_upstream_peers']
  t.assert_equal [1, 1], result['proxy_counts']
  t.assert_equal false, result['proxy_extra_reply']
end
t.assert('stream', 'shutdown ends the pending wait without starting the code again') do
  t.assert_equal nil, result['error']
  t.assert_equal 0, result['exit_status']
  t.assert_equal [1, 0], result['shutdown_counts']
  t.assert_true result['quit_seconds'] < 1.5
  t.assert_equal 0, result['runtime_errors']
end
t.report
