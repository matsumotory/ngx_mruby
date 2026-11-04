# The code of each UDP session runs once, including when more datagrams
# arrive while it waits. The preceding and following single-datagram
# sessions also assert that normal execution and subsequent sessions work.
# Config: test/conf/conf.d/stream/47-async-sleep-udp-once.conf. Port 12392.
t = SimpleTest.new "ngx_mruby test: UDP session code while Async.sleep waits"
# Read only the recent log window, as the complete suite can exceed the
# mruby client's maximum String size before this case runs.
def udp_once_lines(text)
  path = File.join(ENV['NGINX_INSTALL_DIR'], 'logs/error.log')
  log = File.open(path) do |f|
    f.seek([File.size(path) - 2_000_000, 0].max)
    f.read
  end
  log.split("\n").select { |line| line.include?(text) }.size
end
[1, 10, 1].each do |count|
  t.assert('stream', "#{count} datagram(s): one start, one resume, exact reply") do
    starts = udp_once_lines('udp once: started')
    resumes = udp_once_lines('udp once: resumed')
    reply = `ruby #{suite_path('test/t/cases/_udp_once.rb')} 12392 #{count}`
    t.assert_equal 'udp-once-ok', reply
    t.assert_equal 1, udp_once_lines('udp once: started') - starts
    t.assert_equal 1, udp_once_lines('udp once: resumed') - resumes
  end
end
t.report
