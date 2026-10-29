# What a stream session does after Nginx::Stream::Async.sleep, by the result
# of its code. Config: test/conf/conf.d/stream/44-async-sleep-result.conf
# (ports 12374-12377).

t = SimpleTest.new "ngx_mruby test: stream session after Nginx::Stream::Async.sleep"

# The session right after the one that raised must be the 12377 one: the
# exception that stays in the shared mrb_state aborts whichever session comes
# next, and that session clears it.
t.assert('stream', 'an exception after the sleep ends the session without the later phases, and the next session runs its own code') do
  status, body = tcp_client(12374)
  t.assert_equal 'EOF', status
  t.assert_equal '', body
  status, body = tcp_client(12377)
  t.assert_equal 'EOF', status
  t.assert_equal 'next', body
end

t.assert('stream', 'stream_status = ABORT after the sleep ends the session') do
  status, body = tcp_client(12375)
  t.assert_equal 'EOF', status
  t.assert_equal '', body
end

t.assert('stream', 'stream_status = OK after the sleep goes on with the next phase') do
  status, body = tcp_client(12376)
  t.assert_equal 'EOF', status
  t.assert_equal 'after the sleep', body
end

t.report
