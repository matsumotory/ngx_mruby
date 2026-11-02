# The code of each UDP session runs once, including when more datagrams
# arrive while it waits. The preceding and following single-datagram
# sessions also assert that normal execution and subsequent sessions work.
# Config: test/conf/conf.d/stream/47-async-sleep-udp-once.conf. Port 12392.
t = SimpleTest.new "ngx_mruby test: UDP session code while Async.sleep waits"
log_path = File.join(ENV['NGINX_INSTALL_DIR'], 'logs/error.log')
[1, 10, 1].each do |count|
  t.assert('stream', "#{count} datagram(s): one start, one resume, exact reply") do
    before = File.read(log_path)
    starts = before.split('udp once: started').length
    resumes = before.split('udp once: resumed').length
    reply = `ruby test/t/cases/_udp_once.rb 12392 #{count}`
    after = File.read(log_path)
    t.assert_equal 'udp-once-ok', reply
    t.assert_equal 1, after.split('udp once: started').length - starts
    t.assert_equal 1, after.split('udp once: resumed').length - resumes
  end
end
t.report
