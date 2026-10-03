# frozen_string_literal: true

# The scenarios of the memory soak test (test/soak/soak.rb), which the
# performance comparison (test/perf/perf.rb) measures as well.
#
# One scenario is one location in test/soak/nginx.conf and one client behavior.
#   mode :keepalive   HTTP/1.1 keep-alive; every response is checked
#   mode :disconnect  one request per connection, closed without reading the
#                     response; one response is checked before the warmup
Scenario = Struct.new(:name, :path, :headers, :body, :response_headers, :mode, keyword_init: true)

SCENARIOS = [
  Scenario.new(name: 'hello', path: '/hello', body: 'hello'),
  Scenario.new(name: 'headers', path: '/headers',
               headers: { 'X-Soak-A' => 'alpha', 'X-Soak-B' => 'beta', 'User-Agent' => 'soak' },
               body: 'alpha,beta,soak',
               response_headers: { 'x-soak-out-a' => 'ALPHA', 'x-soak-out-b' => 'BETA' }),
  Scenario.new(name: 'var', path: '/var?q=soak', body: 'GET:soak'),
  Scenario.new(name: 'filter', path: '/filter', body: 'FILTERED BODY'),
  Scenario.new(name: 'sleep', path: '/sleep', body: 'slept'),
  Scenario.new(name: 'sub_request', path: '/sub_request', body: 'static body'),
  Scenario.new(name: 'file', path: '/file', body: 'file:/file'),
  Scenario.new(name: 'disconnect', path: '/disconnect', body: 'late', mode: :disconnect)
].each { |s| s.mode ||= :keepalive; s.headers ||= {}; s.response_headers ||= {} }.freeze

# Returns true when the response is the one the scenario expects.
def expected_response?(scenario, status, headers, body)
  status == 200 && body == scenario.body &&
    scenario.response_headers.all? { |k, v| headers[k] == v }
end
