# Access handler of the route_json and agent_* scenarios
# (test/soak/nginx.agent.conf): parses the request body as JSON, looks up the
# upstream block of its "model" and sets $agent_backend for proxy_pass. A
# model without an upstream block gets 403.
r = Nginx::Request.new
v = Nginx::Var.new
group = AgentProxy::GROUPS[JSON.parse(r.body)["model"]]
if group
  v.agent_backend = group
  Nginx.return Nginx::DECLINED
else
  Nginx.return Nginx::HTTP_FORBIDDEN
end
