# Server rewrite hook of test/conf/conf.d/60-agent-proxy.conf: looks up the
# client key from Authorization (Bearer) or x-api-key. A known key sets the
# key id and the limit_conn key and continues; any other request gets 401.
# The keys are made-up test values.
r = Nginx::Request.new
v = Nginx::Var.new
keys = { "agent-test-key-1" => "key-1", "agent-test-key-2" => "key-2" }
auth = r.headers_in["Authorization"].to_s
id = keys[auth.start_with?("Bearer ") ? auth[7..-1] : r.headers_in["x-api-key"].to_s]
if id
  v.agent_proxy_key_id = id
  v.agent_proxy_stream_key = id
  Nginx.return Nginx::DECLINED
else
  Nginx.return Nginx::HTTP_UNAUTHORIZED
end
