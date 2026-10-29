# Agent proxy recipes that work on the current build: nginx in front of a
# mock LLM upstream (test/soak/mock_llm.rb), with Ruby choosing values and
# nginx moving the bytes, for the Anthropic Messages API (/v1/messages) and
# the OpenAI Responses API (/v1/responses).
# Server config: test/conf/conf.d/60-agent-proxy.conf (port 18132).
# Hooks: test/html/agent_proxy_*.rb. Client and mock (ports 12372 and
# 12373): test/t/cases/_agent_proxy_client.rb (CRuby), which prints
# "key=value" lines; see its comment for the modes.

t = SimpleTest.new "ngx_mruby test: agent proxy recipes"

AGENT_PROXY_PORT = 18132

def agent_proxy_client(mode, api = "messages")
  result = {}
  `ruby test/t/cases/_agent_proxy_client.rb #{mode} #{api} #{AGENT_PROXY_PORT}`.split("\n").each do |line|
    key, value = line.split("=", 2)
    result[key] = value
  end
  result
end

# The values that the client prints and the case compares for the Messages
# API, in files of test/html that the agent proxy page of the site shows
# (docs/guides/agent-proxy.md): one "key=value" per line, "key~=text" for a
# value that contains the text, and comment lines with #.
def agent_proxy_expected(name)
  File.open(html_path(name)) { |f| f.read }.split("\n").reject { |l| l.empty? || l.start_with?('#') }.map do |line|
    key, value = line.split('=', 2)
    key.end_with?('~') ? [key[0..-2], :include, value] : [key, :equal, value]
  end
end

def agent_proxy_compare(t, result, name)
  t.assert('ngx_mruby - agent proxy', "the client ran without an error for #{name}") do
    t.assert_nil result['error']
  end
  agent_proxy_expected(name).each do |key, how, value|
    t.assert('ngx_mruby - agent proxy', "#{key} of #{name}") do
      if how == :include
        t.assert_include result[key], value
      else
        t.assert_equal value, result[key]
      end
    end
  end
end

# The client key (server rewrite handler, 401 with a JSON body), routing by
# the model of the body with the credential replaced (access handler, 403
# for an unknown model), limit_conn per client key (429), and an upstream
# 529 with the log handler that reads $upstream_status.
agent_proxy_compare(t, agent_proxy_client('auth'), 'agent_proxy_auth.expected')
agent_proxy_compare(t, agent_proxy_client('route'), 'agent_proxy_route.expected')
agent_proxy_compare(t, agent_proxy_client('limit'), 'agent_proxy_limit.expected')
agent_proxy_compare(t, agent_proxy_client('log'), 'agent_proxy_log.expected')

# The same recipes for the OpenAI Responses API: the client sends Responses
# requests to /v1/responses, the mock answers in that API's format, and the
# proxy's own 401 and 429 bodies use its error format.
AGENT_PROXY_RESPONSES_401 = '{"error":{"message":"invalid API key","type":"invalid_request_error","param":null,"code":null}}'
AGENT_PROXY_RESPONSES_429 = '{"error":{"message":"too many concurrent requests","type":"rate_limit_error","param":null,"code":null}}'

responses_auth = agent_proxy_client('auth', 'responses')

t.assert('ngx_mruby - agent proxy, Responses API', 'server rewrite handler rejects an unknown client key with 401 and a JSON body') do
  t.assert_nil responses_auth['error']
  t.assert_equal "401 application/json #{AGENT_PROXY_RESPONSES_401}", responses_auth['wrong_key']
  t.assert_equal "401 application/json #{AGENT_PROXY_RESPONSES_401}", responses_auth['no_key']
end

t.assert('ngx_mruby - agent proxy, Responses API', 'a rejected request does not reach the upstream; a known key in x-api-key does') do
  t.assert_nil responses_auth['error']
  t.assert_equal '0', responses_auth['mock_requests_after_rejects']
  t.assert_equal '200 12372 true', responses_auth['api_key']
  t.assert_equal '1', responses_auth['mock_requests']
end

responses_route = agent_proxy_client('route', 'responses')

t.assert('ngx_mruby - agent proxy, Responses API', 'access handler routes by the model of the JSON body and swaps the credential') do
  t.assert_nil responses_route['error']
  t.assert_equal '200 12372 Bearer upstream-test-key-a none true', responses_route['model_a']
  t.assert_equal '200 12373 Bearer upstream-test-key-b none true', responses_route['model_b']
end

t.assert('ngx_mruby - agent proxy, Responses API', 'access handler rejects a model without an upstream with 403') do
  t.assert_nil responses_route['error']
  t.assert_equal '403', responses_route['unknown_model']
end

responses_limit = agent_proxy_client('limit', 'responses')

t.assert('ngx_mruby - agent proxy, Responses API', 'limit_conn per client key: a second request of the key gets the 429 of the error_page') do
  t.assert_nil responses_limit['error']
  t.assert_equal '200 text/event-stream stopped 3', responses_limit['held']
  t.assert_equal "429 1 application/json #{AGENT_PROXY_RESPONSES_429}", responses_limit['same_key']
  t.assert_equal '200 12372', responses_limit['other_key']
  t.assert_equal '1', responses_limit['limit_log_lines']
end

t.assert('ngx_mruby - agent proxy, Responses API', 'limit_conn per client key: the slot is free again after the client closed its stream') do
  t.assert_nil responses_limit['error']
  t.assert_equal '200 12372', responses_limit['after_close']
end

responses_log = agent_proxy_client('log', 'responses')

t.assert('ngx_mruby - agent proxy, Responses API', 'an upstream 503 and 429 and their bodies reach the client unchanged') do
  t.assert_nil responses_log['error']
  t.assert_equal '200', responses_log['ok']
  t.assert_equal '503 application/json {"error":{"message":"mock: status 503","type":"service_unavailable_error","param":null,"code":null}}',
                 responses_log['status_503']
  t.assert_equal '429 application/json {"error":{"message":"mock: status 429","type":"rate_limit_error","param":null,"code":null}}',
                 responses_log['status_429']
end

t.assert('ngx_mruby - agent proxy, Responses API', 'log handler reads $upstream_status') do
  t.assert_nil responses_log['error']
  t.assert_include responses_log['ok_log'], 'key=key-1 upstream_status=200 status=200'
  t.assert_include responses_log['status_503_log'], 'key=key-1 upstream_status=503 status=503'
  t.assert_include responses_log['status_429_log'], 'key=key-1 upstream_status=429 status=429'
end

stream = agent_proxy_client('stream')
responses_stream = agent_proxy_client('stream', 'responses')

t.assert('ngx_mruby - agent proxy', 'a stream of 50 deltas arrives byte for byte, through message_stop') do
  t.assert_nil stream['error']
  # status, Content-Type, the body equals the mock's stream, events
  t.assert_equal '200 text/event-stream true 55', stream['stream']
end

t.assert('ngx_mruby - agent proxy, Responses API', 'a stream arrives byte for byte with each terminal event') do
  t.assert_nil responses_stream['error']
  t.assert_equal '200 text/event-stream true 58', responses_stream['stream_completed']
  t.assert_equal '200 text/event-stream true 58', responses_stream['stream_incomplete']
  t.assert_equal '200 text/event-stream true 55', responses_stream['stream_failed']
end

t.report
