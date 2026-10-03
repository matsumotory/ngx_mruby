# Access hook of /v1/messages in test/conf/conf.d/60-agent-proxy.conf: reads
# the model from the JSON body and picks the upstream block and the
# credential that the upstream gets. An unknown model gets 403. The
# credentials are made-up test values.
r = Nginx::Request.new
v = Nginx::Var.new
routes = {
  "mock-model-a" => ["agent_proxy_llm_a", "Bearer upstream-test-key-a"],
  "mock-model-b" => ["agent_proxy_llm_b", "Bearer upstream-test-key-b"]
}
route = routes[JSON.parse(r.body)["model"]]
if route
  v.agent_proxy_backend = route[0]
  v.agent_proxy_upstream_auth = route[1]
  Nginx.return Nginx::DECLINED
else
  Nginx.return Nginx::HTTP_FORBIDDEN
end
