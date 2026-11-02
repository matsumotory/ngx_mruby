# One thousand 1 ms waits in the same content handler must finish and
# release their pending timers and held fibers. This observes live counters,
# not the request pool size (docs/proposals/archive/core-stabilization.md, 6).
# Config: test/conf/conf.d/86-async-sleep-many.conf (port 18188).

t = SimpleTest.new "ngx_mruby test: many sleeps in one HTTP handler"

def sleep_many_response(path)
  # The shared CRuby client bounds each exchange at 60 seconds, including
  # under valgrind, and waits for EOF before the next request is sent.
  status, raw = tcp_client(18188, "GET #{path} HTTP/1.0\r\nHost: localhost\r\n\r\n")
  head, body = raw.split("\r\n\r\n", 2)
  [status, head.to_s.split("\r\n")[0].to_s, body.to_s]
end

t.assert('async', '1000 sleeps answer and restore timers and GC root fibers') do
  before = sleep_many_response('/stats')
  response = sleep_many_response('/sleep_many')
  after = sleep_many_response('/stats')

  [before, response, after].each do |result|
    t.assert_equal 'EOF', result[0]
    t.assert_equal 'HTTP/1.1 200 OK', result[1]
  end
  t.assert_equal 'slept:1000', response[2]
  # Reject absent or malformed counters instead of converting them to zero.
  t.assert_equal true, /\Atimers=0;gc_root_fibers=\d+\z/.match(before[2]) != nil
  t.assert_equal before[2], after[2]
end

t.report
