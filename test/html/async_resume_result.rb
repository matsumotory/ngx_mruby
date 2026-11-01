# The handler of test/conf/conf.d/82-async-resume-result.conf, for every
# phase. The URI is /<location>/<wait>/<end>:
#
# - <wait>: nowait, sleep (Nginx::Async.sleep 1) or sub_request (a
#   subrequest to /leaf, which answers "leaf").
# - <end>: how the handler ends after the wait: none (it sets no result),
#   declined (Nginx::DECLINED), ok (Nginx::OK), forbidden (403), output
#   (Nginx.rputs "output") or raise (an exception).
#
# A handler that goes on lets the request reach async_resume_result.txt,
# which answers "passed".
parts = Nginx::Request.new.uri.split("/")
case parts[-2]
when "sleep"
  Nginx::Async.sleep 1
when "sub_request"
  Nginx::Async::HTTP.sub_request "/leaf"
end

case parts[-1]
when "declined"
  Nginx.return Nginx::DECLINED
when "ok"
  Nginx.return Nginx::OK
when "forbidden"
  Nginx.return Nginx::HTTP_FORBIDDEN
when "output"
  Nginx.rputs "output"
when "raise"
  raise "raised at the end of the handler"
end
