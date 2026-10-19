# frozen_string_literal: true

# The scenarios of the memory soak test (test/soak/soak.rb), which the
# performance comparison (test/perf/perf.rb) measures as well.
#
# One scenario is one location in test/soak/nginx.conf (or in conf, another
# template in test/soak/) and one client behavior.
#   mode :keepalive   HTTP/1.1 keep-alive; every response is checked
#   mode :disconnect  one request per connection, closed without reading the
#                     response; one response is checked before the warmup
#   mode :abort       one request per connection: the client reads the
#                     response head and the first ABORT_AFTER_EVENTS events
#                     of a stream, checks them, and closes the connection
#   mode :cut         one request per connection: the upstream resets the
#                     connection in the middle of the stream, and the client
#                     checks that the body it read to EOF is exactly body,
#                     without the end of the chunked body
#
# Fields besides name, path and mode:
#   headers           request headers
#   method            request method (GET when nil)
#   request_body      request body (none when nil), sent with Content-Length
#   body              the expected response body (:abort: the body up to
#                     where the upstream stops writing; the client reads a
#                     prefix of it)
#   response_headers  response headers that must have these values (a nil
#                     value: the header must be absent)
#   conf              the nginx.conf template in test/soak/ (nginx.conf when nil)
#   mock              options of test/soak/mock_llm.rb, which the drivers
#                     start with --port __SOAK_MOCK_PORT__ for the scenario
#                     (no mock when nil)
#   allowed_log       regular expressions for error.log lines that do not
#                     fail the scenario although they match a failing pattern
Scenario = Struct.new(:name, :path, :headers, :body, :response_headers, :mode, :method, :request_body,
                      :conf, :mock, :allowed_log, keyword_init: true)

require_relative 'mock_llm'

ABORT_AFTER_EVENTS = 3

# Request bodies of the agent proxy scenarios: Messages requests of exactly
# 2 KB and 64 KB for the model that test/soak/handlers/agent_init.rb routes
# to the mock.
AGENT_BODY_2K = MockLLM.request_body(2048)
AGENT_BODY_64K = MockLLM.request_body(65_536)
AGENT_STREAM_2K = MockLLM.request_body(2048, stream: true)
AGENT_JSON = { 'Content-Type' => 'application/json' }.freeze
AGENT_SSE = { 'content-type' => 'text/event-stream' }.freeze

# The answer of the mock for a message (no stream) and for a stream of n
# content_block_delta events, the first `events` events of that stream.
def agent_message(request_body)
  MockLLM.message_body(request_body)
end

def agent_stream(request_body, deltas, events: nil)
  list = MockLLM.stream_events(request_body, events: deltas)
  (events ? list.first(events) : list).join
end

# nginx logs one of these at the error level when the upstream resets or
# closes its connection in the middle of a response: the recv() error of an
# upstream connection (nginx logs errors of upstream connections at the
# error level, and those of client connections at info), or the check for an
# incomplete response in unbuffered mode. The text after "while" is the
# action that nginx was doing on the request at that time; both appear in a
# run of agent_upstream_reset.
UPSTREAM_RESET_LOG = [
  %r{\[error\] .* recv\(\) failed \(104: Connection reset by peer\) while (reading upstream|sending to client), .* upstream: "http://127\.0\.0\.1:\d+/v1/messages"},
  %r{\[error\] .* upstream prematurely closed connection while reading upstream, .* upstream: "http://127\.0\.0\.1:\d+/v1/messages"}
].freeze

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
  Scenario.new(name: 'disconnect', path: '/disconnect', body: 'late', mode: :disconnect),

  # Agent proxy scenarios (test/soak/nginx.agent.conf, the mock LLM).
  # proxy_*: no Ruby; the baselines of the scenarios of the same shape.
  Scenario.new(name: 'proxy_plain_2k', conf: 'nginx.agent.conf', mock: [],
               method: 'POST', path: '/v1/plain', headers: AGENT_JSON, request_body: AGENT_BODY_2K,
               body: agent_message(AGENT_BODY_2K), response_headers: { 'x-mock-x-api-key' => nil }),
  Scenario.new(name: 'proxy_plain_64k', conf: 'nginx.agent.conf', mock: [],
               method: 'POST', path: '/v1/plain', headers: AGENT_JSON, request_body: AGENT_BODY_64K,
               body: agent_message(AGENT_BODY_64K)),
  Scenario.new(name: 'proxy_stream_plain_50', conf: 'nginx.agent.conf', mock: %w[--events 50],
               method: 'POST', path: '/v1/plain', headers: AGENT_JSON, request_body: AGENT_STREAM_2K,
               body: agent_stream(AGENT_STREAM_2K, 50), response_headers: AGENT_SSE),
  Scenario.new(name: 'proxy_stream_plain_1000', conf: 'nginx.agent.conf', mock: %w[--events 1000],
               method: 'POST', path: '/v1/plain', headers: AGENT_JSON, request_body: AGENT_STREAM_2K,
               body: agent_stream(AGENT_STREAM_2K, 1000), response_headers: AGENT_SSE),
  # auth: proxy_plain_2k behind a server rewrite handler that checks the
  # client key and picks the upstream credential.
  Scenario.new(name: 'auth', conf: 'nginx.agent.conf', mock: [],
               method: 'POST', path: '/v1/plain',
               headers: AGENT_JSON.merge('Host' => 'auth.agent.test', 'Authorization' => 'Bearer agent-test-key-1'),
               request_body: AGENT_BODY_2K, body: agent_message(AGENT_BODY_2K),
               response_headers: { 'x-mock-x-api-key' => 'upstream-test-key-a', 'x-mock-authorization' => nil }),
  # route_json_*: proxy_plain_* with an access handler that parses the body
  # and picks the upstream block by its model.
  Scenario.new(name: 'route_json_2k', conf: 'nginx.agent.conf', mock: [],
               method: 'POST', path: '/v1/route', headers: AGENT_JSON, request_body: AGENT_BODY_2K,
               body: agent_message(AGENT_BODY_2K)),
  Scenario.new(name: 'route_json_64k', conf: 'nginx.agent.conf', mock: [],
               method: 'POST', path: '/v1/route', headers: AGENT_JSON, request_body: AGENT_BODY_64K,
               body: agent_message(AGENT_BODY_64K)),
  # ruby_call_*: 1 and 10 Ruby calls (mruby_set_code) and nothing else.
  Scenario.new(name: 'ruby_call_1', conf: 'nginx.agent.conf', path: '/ruby_call_1', body: '1'),
  Scenario.new(name: 'ruby_call_10', conf: 'nginx.agent.conf', path: '/ruby_call_10', body: '12345678910'),
  # agent_*: streams through the access handler of route_json_*.
  Scenario.new(name: 'agent_stream', conf: 'nginx.agent.conf', mock: %w[--events 50],
               method: 'POST', path: '/v1/route', headers: AGENT_JSON, request_body: AGENT_STREAM_2K,
               body: agent_stream(AGENT_STREAM_2K, 50), response_headers: AGENT_SSE),
  Scenario.new(name: 'agent_client_abort', conf: 'nginx.agent.conf', mock: %w[--events 50 --hold-after 10],
               method: 'POST', path: '/v1/route', headers: AGENT_JSON, request_body: AGENT_STREAM_2K,
               body: agent_stream(AGENT_STREAM_2K, 50, events: 10), response_headers: AGENT_SSE, mode: :abort),
  Scenario.new(name: 'agent_upstream_reset', conf: 'nginx.agent.conf', mock: %w[--events 50 --reset-after 10],
               method: 'POST', path: '/v1/route', headers: AGENT_JSON, request_body: AGENT_STREAM_2K,
               body: agent_stream(AGENT_STREAM_2K, 50, events: 10), response_headers: AGENT_SSE, mode: :cut,
               allowed_log: UPSTREAM_RESET_LOG)
].each do |s|
  s.mode ||= :keepalive
  s.method ||= 'GET'
  s.headers ||= {}
  s.response_headers ||= {}
  s.conf ||= 'nginx.conf'
  s.allowed_log ||= []
end.freeze

# Returns true when the response is the one the scenario expects.
def expected_response?(scenario, status, headers, body)
  status == 200 && body == scenario.body &&
    scenario.response_headers.all? { |k, v| headers[k] == v }
end

# Sends the scenario's request on client (see Client#request).
def scenario_request(client, scenario, close: false)
  client.request(scenario.method, scenario.path, scenario.headers, scenario.request_body, close: close)
end

# Sends the request of an :abort or :cut scenario on client and checks what
# arrives. Returns nil when it is what the scenario expects, else a message.
# The caller closes the client.
def stream_problem(client, scenario)
  if scenario.mode == :abort
    status, headers, body, ending = client.stream(scenario.method, scenario.path, scenario.headers,
                                                  scenario.request_body) { |b| b.scan("\n\n").size >= ABORT_AFTER_EVENTS }
    ok = ending == :stopped && scenario.body.start_with?(body)
  else
    status, headers, body, ending = client.stream(scenario.method, scenario.path, scenario.headers,
                                                  scenario.request_body) { false }
    ok = ending == :cut && body == scenario.body
  end
  return nil if ok && status == 200 && scenario.response_headers.all? { |k, v| headers[k] == v }

  "#{scenario.path}: unexpected response #{status} (#{ending}, #{body.bytesize} bytes) #{body[0, 200].inspect} #{headers.inspect}"
end
