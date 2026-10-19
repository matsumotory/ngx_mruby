# Server rewrite handler of the auth scenario (test/soak/nginx.agent.conf):
# looks up the client key from Authorization (Bearer) or x-api-key, and sets
# the variables that the location sends upstream. Two Hash lookups and three
# variable assignments; a request without a known key gets 401.
r = Nginx::Request.new
v = Nginx::Var.new
auth = r.headers_in["Authorization"].to_s
key = AgentProxy::KEYS[auth.start_with?("Bearer ") ? auth[7..-1] : r.headers_in["x-api-key"].to_s]
if key
  v.agent_key_id = key["id"]
  v.agent_backend = key["group"]
  v.agent_upstream_key = AgentProxy::UPSTREAM_KEYS[key["group"]]
  Nginx.return Nginx::DECLINED
else
  Nginx.return Nginx::HTTP_UNAUTHORIZED
end
