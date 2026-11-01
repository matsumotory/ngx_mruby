# The content handler after async_subrequest_once.rb: it reports how many
# times the code ran and how many subrequests reached /once_leaf for this
# request, and drops the counts.
id = Nginx::Var.new.request_id
runs = ($async_once_runs || {}).delete(id).to_i
subs = ($async_once_subs || {}).delete("id=#{id}").to_i
Nginx.rputs "runs=#{runs} subs=#{subs}"
