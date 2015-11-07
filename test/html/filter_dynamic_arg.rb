r = Nginx::Request.new
f = Nginx::Filter.new
args = r.var.args
if args.nil?
  f.body = "output filter: static"
else
  r.headers_out["X-New-Header"] = args.to_s
  f.body = "output filter: #{args}"
end
