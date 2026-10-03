# Log hook of /v1/messages in test/conf/conf.d/60-agent-proxy.conf: writes
# one notice line per request with the test id that the client sent, the key
# id, $upstream_status and $status.
r = Nginx::Request.new
v = Nginx::Var.new
Nginx.errlogger Nginx::LOG_NOTICE,
                "agent_proxy_log test_id=#{r.headers_in["x-test-id"]} key=#{v.agent_proxy_key_id} " \
                "upstream_status=#{v.upstream_status} status=#{v.status}"
