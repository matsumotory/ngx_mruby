# The code of the mruby_set handler of test/conf/conf.d/83-async-set-var.conf.
# The URI is /<location>/<wait>/<end>:
#
# - <wait>: nowait, sleep (Nginx::Async.sleep 1) or sleep_twice.
# - <end>: value (the code returns "set"), forbidden (Nginx.return 403, and
#   then the code returns "set"), raise (an exception), sub_request
#   (Nginx::Async::HTTP.sub_request, which raises in an mruby_set handler)
#   or to_s_raises (the code returns an object whose to_s raises).
parts = Nginx::Request.new.uri.split("/")
case parts[-2]
when "sleep"
  Nginx::Async.sleep 1
when "sleep_twice"
  Nginx::Async.sleep 1
  Nginx::Async.sleep 1
end

case parts[-1]
when "forbidden"
  Nginx.return Nginx::HTTP_FORBIDDEN
  "set"
when "raise"
  raise "raised at the end of the mruby_set handler"
when "sub_request"
  Nginx::Async::HTTP.sub_request "/plain"
  "set"
when "to_s_raises"
  o = Object.new
  def o.to_s
    raise "raised in to_s"
  end
  o
else
  "set"
end
