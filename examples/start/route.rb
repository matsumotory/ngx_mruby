# Local demonstration credentials. Never use these values for a public service.
r = Nginx::Request.new
v = Nginx::Var.new

if r.headers_in["Authorization"] != "Bearer local-client"
  Nginx.return Nginx::HTTP_UNAUTHORIZED
else
  routes = {
    "mock-model-a" => ["local_api_a", "Bearer local-upstream-a"],
    "mock-model-b" => ["local_api_b", "Bearer local-upstream-b"]
  }
  begin
    body = JSON.parse(r.body)
    route = body.kind_of?(Hash) ? routes[body["model"]] : nil
    if route
      v.selected_backend = route[0]
      v.upstream_credential = route[1]
      Nginx.return Nginx::DECLINED
    else
      Nginx.return Nginx::HTTP_FORBIDDEN
    end
  rescue ArgumentError
    Nginx.return Nginx::HTTP_BAD_REQUEST
  end
end
