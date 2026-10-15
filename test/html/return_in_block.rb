# Rewrite handler of /return_in_block/file in
# test/conf/conf.d/55-return-in-block.conf: a `return` inside a block at the
# top level of a handler file (issue #502).
[0].each do |_|
  r = Nginx::Request.new
  r.headers_out["Location"] = "http://example.com/file"
  Nginx.return Nginx::HTTP_MOVED_TEMPORARILY
  return
end
Nginx::Request.new.headers_out["X-After-Return"] = "reached"
