# These local mocks report the selected route; they do not call an LLM.
r = Nginx::Request.new
v = Nginx::Var.new
name = v.server_port == "8081" ? "a" : "b"
body = JSON.parse(r.body)
r.headers_out["Content-Type"] = "application/json"
Nginx.rputs JSON.pretty_generate({
  "upstream" => name,
  "model" => body["model"],
  "credential_replaced" => r.headers_in["Authorization"] == "Bearer local-upstream-#{name}"
})
