t = SimpleTest.new "ngx_mruby test: Uname of mruby-uname (test/conf/conf.d/61-gem-uname.conf)"

GEM_UNAME_PORT = 18128

t.assert('mruby-uname', 'Uname answers what uname(1) prints, on the first and a later request') do
  # The test client runs on the machine of the nginx under test.
  expected = %w[-s -n -r -v -m].map { |opt| `uname #{opt}`.chomp }.join("\n")

  res = HttpRequest.new.get base(GEM_UNAME_PORT) + '/gem_uname'
  t.assert_equal 200, res.code
  t.assert_equal expected, res["body"]

  # A later request reads the object that the first one kept in the class
  # (the test nginx runs a single process).
  res = HttpRequest.new.get base(GEM_UNAME_PORT) + '/gem_uname'
  t.assert_equal 200, res.code
  t.assert_equal expected, res["body"]
end

t.report
