# Agent proxy recipes that work on the current build: nginx in front of a
# mock LLM upstream (test/soak/mock_llm.rb), with Ruby choosing values and
# nginx moving the bytes.
# Server config: test/conf/conf.d/60-agent-proxy.conf (port 18132).
# Hooks: test/html/agent_proxy_*.rb. Client and mock (ports 12372 and
# 12373): test/t/cases/_agent_proxy_client.rb (CRuby), which prints
# "key=value" lines; see its comment for the modes.

t = SimpleTest.new "ngx_mruby test: agent proxy recipes"

def agent_proxy_client(mode)
  result = {}
  `ruby test/t/cases/_agent_proxy_client.rb #{mode}`.split("\n").each do |line|
    key, value = line.split("=", 2)
    result[key] = value
  end
  result
end

AGENT_PROXY_401 = '{"type":"error","error":{"type":"authentication_error","message":"invalid API key"}}'
AGENT_PROXY_429 = '{"type":"error","error":{"type":"rate_limit_error","message":"too many concurrent requests"}}'

auth = agent_proxy_client('auth')

t.assert('ngx_mruby - agent proxy', 'server rewrite handler rejects an unknown client key with 401 and a JSON body') do
  t.assert_nil auth['error']
  t.assert_equal "401 application/json #{AGENT_PROXY_401}", auth['wrong_key']
  t.assert_equal "401 application/json #{AGENT_PROXY_401}", auth['no_key']
end

t.assert('ngx_mruby - agent proxy', 'a rejected request does not reach the upstream; a known key in x-api-key does') do
  t.assert_nil auth['error']
  t.assert_equal '0', auth['mock_requests_after_rejects']
  t.assert_equal '200 12372 true', auth['api_key']
  t.assert_equal '1', auth['mock_requests']
end

route = agent_proxy_client('route')

t.assert('ngx_mruby - agent proxy', 'access handler routes by the model of the JSON body and swaps the credential') do
  t.assert_nil route['error']
  # status, upstream port, Authorization and x-api-key at the upstream, body
  t.assert_equal '200 12372 Bearer upstream-test-key-a none true', route['model_a']
  t.assert_equal '200 12373 Bearer upstream-test-key-b none true', route['model_b']
end

t.assert('ngx_mruby - agent proxy', 'access handler rejects a model without an upstream with 403') do
  t.assert_nil route['error']
  t.assert_equal '403', route['unknown_model']
end

limit = agent_proxy_client('limit')

t.assert('ngx_mruby - agent proxy', 'limit_conn per client key: a second request of the key gets the 429 of the error_page') do
  t.assert_nil limit['error']
  # status, Content-Type, how the client stopped reading, events read
  t.assert_equal '200 text/event-stream stopped 3', limit['held']
  t.assert_equal "429 1 application/json #{AGENT_PROXY_429}", limit['same_key']
  t.assert_equal '200 12372', limit['other_key']
  # limit_conn_log_level notice: one line for the rejected request
  t.assert_equal '1', limit['limit_log_lines']
end

t.assert('ngx_mruby - agent proxy', 'limit_conn per client key: the slot is free again after the client closed its stream') do
  t.assert_nil limit['error']
  t.assert_equal '200 12372', limit['after_close']
end

log = agent_proxy_client('log')

t.assert('ngx_mruby - agent proxy', 'an upstream 529 and its body reach the client unchanged') do
  t.assert_nil log['error']
  t.assert_equal '200', log['ok']
  t.assert_equal '529 application/json {"type":"error","error":{"type":"overloaded_error","message":"mock: status 529"}}',
                 log['overloaded']
end

t.assert('ngx_mruby - agent proxy', 'log handler reads $upstream_status') do
  t.assert_nil log['error']
  t.assert_include log['ok_log'], 'key=key-1 upstream_status=200 status=200'
  t.assert_include log['overloaded_log'], 'key=key-1 upstream_status=529 status=529'
end

t.report
