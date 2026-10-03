t = SimpleTest.new "ngx_mruby test: conf.d fragments and test/t/cases"

t.assert('harness', 'location /smoke on 58110 from test/conf/conf.d/00-smoke.conf') do
  res = HttpRequest.new.get base(58110) + '/smoke'
  t.assert_equal 'conf.d ok', res["body"]
end

t.report
