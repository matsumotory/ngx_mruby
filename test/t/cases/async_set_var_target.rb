# The variable of mruby_set_code and a later async handler of the same
# request. Config: test/conf/conf.d/47-async-set-var-target.conf (port 18123).

t = SimpleTest.new "ngx_mruby test: mruby_set variable after a later async handler"

def async_set_var_split(raw)
  head, body = raw.split("\r\n\r\n", 2)
  [head.to_s.split("\r\n")[0].to_s, body.to_s]
end

t.assert('async', 'an async access handler does not assign its result to the mruby_set variable') do
  status, raw = tcp_client(18123, "GET /set_then_async_access HTTP/1.0\r\nHost: localhost\r\n\r\n")
  line, body = async_set_var_split(raw)
  t.assert_equal 'EOF', status
  t.assert_equal 'HTTP/1.1 200 OK', line
  t.assert_equal 'original', body
end

t.report
