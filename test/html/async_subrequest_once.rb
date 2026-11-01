# The handler of test/conf/conf.d/84-async-subrequest-return.conf that waits
# for a subrequest and ends without a result, or with Nginx::DECLINED when
# the URI ends with /declined. It counts its runs for the request and stops
# with 500 after three, so that a request whose handler ran again ends.
id = Nginx::Var.new.request_id
$async_once_runs ||= Hash.new(0)
$async_once_runs[id] += 1
if $async_once_runs[id] > 3
  Nginx.return Nginx::HTTP_INTERNAL_SERVER_ERROR
else
  Nginx::Async::HTTP.sub_request "/once_leaf", "id=#{id}"
  Nginx.return Nginx::DECLINED if Nginx::Request.new.uri.end_with?("/declined")
end
