t = SimpleTest.new "ngx_mruby test: conf.d fragments and test/t/cases"

t.assert('harness', 'location /smoke on 18110 from test/conf/conf.d/00-smoke.conf') do
  res = HttpRequest.new.get base(18110) + '/smoke'
  t.assert_equal 'conf.d ok', res["body"]
end

t.report
