# A UDP stream session runs its code once: ten datagrams that arrive while
# the code waits in Nginx::Stream::Async.sleep start no other run of the
# code, so the session has one fiber, and the reply comes after the sleep.
# Config: test/conf/conf.d/stream/47-async-sleep-udp-once.conf (port 12392).
# _udp_once.rb is in this directory and runs with CRuby.

t = SimpleTest.new "ngx_mruby test: a UDP stream session runs its code once"

# The lines of the error log that contain text, from its last 2,000,000
# bytes, where the lines of this case are.
def udp_once_lines(text)
  path = File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
  log = File.open(path) do |f|
    f.seek([File.size(path) - 2_000_000, 0].max)
    f.read
  end
  log.split("\n").select { |l| l.include?(text) }.size
end

t.assert('stream Async.sleep UDP: ten datagrams during the sleep start the code once, and the session answers after the sleep') do
  started_before = udp_once_lines('udp once: the code started')
  resumed_before = udp_once_lines('udp once: the code resumed')
  reply = `ruby #{suite_path('test/t/cases/_udp_once.rb')} 12392 10`
  t.assert_equal 'udp-once-ok', reply
  t.assert_equal 1, udp_once_lines('udp once: the code started') - started_before
  t.assert_equal 1, udp_once_lines('udp once: the code resumed') - resumed_before
end

t.report
