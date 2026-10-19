# A `return` inside a block or a `for` body at the top level of handler code
# ends the code, as a `return` at the top level does (issue #502). With mruby
# 3.3.0 (2.x) it raised LocalJumpError and the handler answered 500.
# Config: test/conf/conf.d/55-return-in-block.conf (port 18117).

t = SimpleTest.new "ngx_mruby test: return in a block of handler code"

def return_in_block_get(name)
  HttpRequest.new.get base(18117) + "/return_in_block/#{name}"
end

# The body of nginx's own page for a 302 that a handler sets with Nginx.return.
FOUND_PAGE_TITLE = '<title>302 Found</title>'

{
  'block' => 'a return in a block',
  'for' => 'a return in the body of for',
  'file' => 'a return in a block of a handler file',
  # the control: a `return` at the top level of the code, outside a block,
  # which answered 302 on 2.x as well
  'top' => 'a return at the top level',
}.each do |name, what|
  t.assert('ngx_mruby - return in handler code', "#{what} of a rewrite handler ends the code with the 302 it set") do
    res = return_in_block_get(name)
    t.assert_equal 302, res.code
    t.assert_equal "http://example.com/#{name}", res["location"]
    t.assert_include res["body"], FOUND_PAGE_TITLE
    t.assert_nil res["x-after-return"]
  end
end

t.assert('ngx_mruby - return in handler code', 'a return in a block of a content handler ends the output') do
  res = return_in_block_get('content')
  t.assert_equal 200, res.code
  t.assert_equal 'before the block', res["body"]
end

t.assert('ngx_mruby - return in handler code', 'a return with a value in a block of mruby_set_code sets that value') do
  res = return_in_block_get('set')
  t.assert_equal 200, res.code
  t.assert_equal 'from the block', res["body"]
end

# What ngx_mruby logs when the code of a request raises. With mruby 3.3.0 each
# location above logged `mrb_run failed: ... unexpected return
# (LocalJumpError)`. The response of /content cannot show it, because 2.x
# keeps the output that the code wrote before the exception, so error.log is
# checked for all the requests above.
t.assert('ngx_mruby - return in handler code', 'no request above logs an exception') do
  raised = []
  File.open(File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')) do |f|
    f.each_line { |line| raised << line if line.include?('mrb_run failed') && line.include?('"GET /return_in_block/') }
  end
  t.assert_equal [], raised
end

t.report
