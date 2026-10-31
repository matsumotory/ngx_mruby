# Guard for the Nginx::Stream::Async.sleep teardown path. Config:
# test/conf/conf.d/stream/43-async-sleep-teardown.conf (ports 12368, 12369).
# The case opens a connection to 12368, whose session code sleeps 3000 ms, lets
# the sleep timer arm, resets the connection during the sleep, waits past the
# sleep, and then checks that the plain return server on 12369 still answers.
# nginx defers a client reset on a suspended stream session until the handler
# resumes, so this exercises the Async.sleep teardown path and confirms nginx
# stays healthy through it; it does not force the pre-fix use-after-free, which
# needs the connection pool to be freed while the timer is still armed (a worker
# shutdown or reload, which this harness does not drive). _tcp_abort.rb and
# tcp_client are in this directory and _prelude.rb.

t = SimpleTest.new "ngx_mruby test: the Nginx::Stream::Async.sleep teardown path stays healthy"

t.assert('ngx_mruby - stream Async.sleep teardown: a client reset during the sleep leaves nginx healthy', '12368 reset mid-sleep, 12369 still answers') do
  # the liveness server answers before the reset
  before_status, before_body = tcp_client(12369)
  t.assert_equal 'EOF', before_status
  t.assert_include before_body, 'alive'

  # connect to 12368, let the 3000 ms sleep timer arm (1.0 s), reset the
  # connection, then wait past the sleep (3.5 s) so the handler has resumed
  out = `ruby #{suite_path('test/t/cases/_tcp_abort.rb')} 12368 1.0 3.5`
  t.assert_equal 'aborted', out

  # nginx stays healthy through the sleep, the reset, the resume and the teardown
  after_status, after_body = tcp_client(12369)
  t.assert_equal 'EOF', after_status
  t.assert_include after_body, 'alive'
end

t.report
