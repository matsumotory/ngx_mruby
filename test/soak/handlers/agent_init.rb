# mruby_init_worker of the agent proxy scenarios (test/soak/nginx.agent.conf):
# the tables that agent_auth.rb and agent_route.rb look up. The keys and
# credentials are made-up test values.
module AgentProxy
  # client key => what the key may use
  KEYS = {
    'agent-test-key-1' => { 'id' => 'key-1', 'group' => 'mock_llm' },
    'agent-test-key-2' => { 'id' => 'key-2', 'group' => 'mock_llm' }
  }
  # upstream block => the credential that the proxy sends there
  UPSTREAM_KEYS = { 'mock_llm' => 'upstream-test-key-a' }
  # model => upstream block
  GROUPS = { 'mock-model' => 'mock_llm' }
end
