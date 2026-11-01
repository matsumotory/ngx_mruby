# The location of the subrequest of async_subrequest_once.rb: it counts the
# subrequests for the request whose id is in the arguments.
$async_once_subs ||= Hash.new(0)
$async_once_subs[Nginx::Request.new.args] += 1
Nginx.rputs "leaf"
