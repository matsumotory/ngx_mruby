#!/usr/bin/env ruby
# frozen_string_literal: true

# Client and mock LLM upstream for test/t/cases/agent_proxy.rb (CRuby). It
# starts test/soak/mock_llm.rb in this process on 127.0.0.1:12372 and
# 127.0.0.1:12373 (the upstream blocks agent_proxy_llm_a and _b of
# test/conf/conf.d/60-agent-proxy.conf), sends the requests of one mode to
# nginx on 18132, stops the mock, and prints one "key=value" line per
# observation. A header that the response does not have prints as "none".
#
# Usage: ruby test/t/cases/_agent_proxy_client.rb auth|route|limit|log
#
#   auth   a wrong key, no key, and a known key in x-api-key
#   route  models mock-model-a and mock-model-b, and an unknown model
#   limit  a stream of key-1 that the mock holds open, then requests of key-1
#          and key-2 while it is open (and the limit_conn lines that the
#          rejection adds to NGINX_INSTALL_DIR/logs/error.log), and of key-1
#          after the client closed the stream
#   log    a 200 and an upstream 529, and the lines of the log hook in
#          NGINX_INSTALL_DIR/logs/error.log
#
# Every exchange has a limit of LIMIT seconds, long enough for nginx under
# valgrind. When a step fails, the script prints error=<message> and exits
# with 1; the lines printed before stay.

require 'json'
require_relative '../../soak/mock_llm'
require_relative '../../soak/http_client'

LIMIT = 60
PORT = 18_132
MOCK_PORTS = [12_372, 12_373].freeze

def now
  Process.clock_gettime(Process::CLOCK_MONOTONIC)
end

def out(key, value)
  puts "#{key}=#{value.to_s.gsub("\n", '\\n')}"
  $stdout.flush
end

def post(headers, body)
  client = Client.new(PORT, io_timeout: LIMIT)
  client.request('POST', '/v1/messages', { 'Content-Type' => 'application/json' }.merge(headers), body, close: true)
ensure
  client&.close
end

# Waits until the block returns true, for at most LIMIT seconds.
def wait_for(what)
  deadline = now + LIMIT
  until yield
    raise "#{what} did not happen within #{LIMIT} s" if now > deadline

    sleep 0.05
  end
end

def run_auth(mock)
  body = MockLLM.request_body(300, model: 'mock-model-a')
  status, headers, response, = post({ 'Authorization' => 'Bearer wrong-key' }, body)
  out('wrong_key', "#{status} #{headers['content-type']} #{response}")
  status, headers, response, = post({}, body)
  out('no_key', "#{status} #{headers['content-type']} #{response}")
  out('mock_requests_after_rejects', mock.stats[:requests])
  status, headers, response, = post({ 'x-api-key' => 'agent-test-key-2' }, body)
  out('api_key', "#{status} #{headers['x-mock-port'] || 'none'} #{response == MockLLM.message_body(body)}")
  out('mock_requests', mock.stats[:requests])
end

def run_route(_mock)
  [['model_a', 'mock-model-a', { 'Authorization' => 'Bearer agent-test-key-1' }],
   ['model_b', 'mock-model-b', { 'x-api-key' => 'agent-test-key-2' }]].each do |key, model, credential|
    body = MockLLM.request_body(300, model: model)
    status, headers, response, = post(credential, body)
    out(key, "#{status} #{headers['x-mock-port'] || 'none'} #{headers['x-mock-authorization'] || 'none'} " \
             "#{headers['x-mock-x-api-key'] || 'none'} #{response == MockLLM.message_body(body)}")
  end
  status, = post({ 'Authorization' => 'Bearer agent-test-key-1' }, MockLLM.request_body(300, model: 'other-model'))
  out('unknown_model', status)
end

def run_limit(mock)
  body = MockLLM.request_body(300, model: 'mock-model-a')
  held = Client.new(PORT, io_timeout: LIMIT)
  begin
    stream_body = MockLLM.request_body(300, model: 'mock-model-a', stream: true)
    status, headers, events, ending = held.stream('POST', '/v1/messages',
                                                  { 'Content-Type' => 'application/json',
                                                    'Authorization' => 'Bearer agent-test-key-1',
                                                    'x-mock-hold-after' => '3' }, stream_body) { |b| b.scan("\n\n").size >= 3 }
    out('held', "#{status} #{headers['content-type']} #{ending} #{events.scan("\n\n").size}")
    wait_for('the hold at the mock') { mock.stats[:held] == 1 }

    before = limit_log_count
    status, headers, response, = post({ 'Authorization' => 'Bearer agent-test-key-1' }, body)
    out('same_key', "#{status} #{headers['retry-after'] || 'none'} #{headers['content-type']} #{response}")
    wait_for('the limit_conn log line') { limit_log_count > before }
    out('limit_log_lines', limit_log_count - before)
    status, headers, = post({ 'Authorization' => 'Bearer agent-test-key-2' }, body)
    out('other_key', "#{status} #{headers['x-mock-port'] || 'none'}")
  ensure
    held.close
  end
  wait_for('the close of the held upstream connection') { mock.stats[:held_closed] == 1 }
  status, headers, = post({ 'Authorization' => 'Bearer agent-test-key-1' }, body)
  out('after_close', "#{status} #{headers['x-mock-port'] || 'none'}")
end

def error_log
  File.join(ENV.fetch('NGINX_INSTALL_DIR'), 'logs', 'error.log')
end

# The number of lines of error.log in which limit_conn rejected a request of
# this server's zone, at the level of limit_conn_log_level.
def limit_log_count
  File.foreach(error_log).count do |l|
    l.include?('[notice] ') && l.include?('limiting connections by zone "agent_proxy_streams"')
  end
end

# The text of the log hook's line for the test id (waits for it).
def log_line(test_id)
  marker = "agent_proxy_log test_id=#{test_id} "
  line = nil
  wait_for("the log line of #{test_id}") do
    line = File.foreach(error_log).find { |l| l.include?(marker) }
  end
  line[/agent_proxy_log (.*?)(, client:|\z)/, 1].strip
end

def run_log(_mock)
  body = MockLLM.request_body(300, model: 'mock-model-a')
  ok_id = "ok-#{Process.pid}"
  overloaded_id = "overloaded-#{Process.pid}"
  status, = post({ 'Authorization' => 'Bearer agent-test-key-1', 'x-test-id' => ok_id }, body)
  out('ok', status)
  status, headers, response, = post({ 'Authorization' => 'Bearer agent-test-key-1', 'x-test-id' => overloaded_id,
                                      'x-mock-status' => '529' }, body)
  out('overloaded', "#{status} #{headers['content-type']} #{response}")
  out('ok_log', log_line(ok_id))
  out('overloaded_log', log_line(overloaded_id))
end

mode = ARGV[0]
runner = { 'auth' => :run_auth, 'route' => :run_route, 'limit' => :run_limit, 'log' => :run_log }[mode]
abort "usage: ruby #{$PROGRAM_NAME} auth|route|limit|log" unless runner

Thread.report_on_exception = false
mock = MockLLM::Server.new(MOCK_PORTS).start
begin
  send(runner, mock)
rescue StandardError => e
  out('error', "#{e.class}: #{e.message}")
  exit 1
ensure
  mock.stop
end
