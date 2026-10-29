#!/usr/bin/env ruby
# frozen_string_literal: true

# Client and mock LLM upstream for test/t/cases/agent_proxy.rb (CRuby). It
# starts test/soak/mock_llm.rb in this process on 127.0.0.1:12372 and
# 127.0.0.1:12373 (the upstream blocks agent_proxy_llm_a and _b of
# test/conf/conf.d/60-agent-proxy.conf), sends the requests of one mode to
# nginx on 18132, stops the mock, and prints one "key=value" line per
# observation. A header that the response does not have prints as "none".
#
# Usage: ruby test/t/cases/_agent_proxy_client.rb auth|route|limit|log|stream [messages|responses] [PORT]
#
#   auth   a wrong key, no key, and a known key in x-api-key
#   route  models mock-model-a and mock-model-b, and an unknown model
#   limit  a stream of key-1 that the mock holds open, then requests of key-1
#          and key-2 while it is open (and the limit_conn lines that the
#          rejection adds to NGINX_INSTALL_DIR/logs/error.log), and of key-1
#          after the client closed the stream
#   log    a 200 and upstream errors (529 for messages, 503 and 429 for
#          responses), and the lines of the log hook in
#          NGINX_INSTALL_DIR/logs/error.log
#   stream complete streams of 50 deltas, compared byte for byte with
#          MockLLM.stream_body (for responses, one per terminal event:
#          completed, incomplete, failed)
#
# The second argument is the API: messages (the default) sends Messages
# requests to /v1/messages, responses sends Responses requests to
# /v1/responses. The third is the port of nginx, 18132 by default.
#
# Every exchange has a limit of LIMIT seconds, long enough for nginx under
# valgrind. When a step fails, the script prints error=<message> and exits
# with 1; the lines printed before stay.

require 'json'
require_relative '../../soak/mock_llm'
require_relative '../../soak/http_client'

LIMIT = 60
PORT = Integer(ARGV[2] || 18_132)
MOCK_PORTS = [12_372, 12_373].freeze

def now
  Process.clock_gettime(Process::CLOCK_MONOTONIC)
end

def out(key, value)
  puts "#{key}=#{value.to_s.gsub("\n", '\\n')}"
  $stdout.flush
end

API = (ARGV[1] || 'messages').to_sym
PATH = "/v1/#{API}"

def request_body(model, stream: false)
  MockLLM.request_body(300, model: model, stream: stream, api: API)
end

def post(headers, body)
  client = Client.new(PORT, io_timeout: LIMIT)
  client.request('POST', PATH, { 'Content-Type' => 'application/json' }.merge(headers), body, close: true)
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
  body = request_body('mock-model-a')
  status, headers, response, = post({ 'Authorization' => 'Bearer wrong-key' }, body)
  out('wrong_key', "#{status} #{headers['content-type']} #{response}")
  status, headers, response, = post({}, body)
  out('no_key', "#{status} #{headers['content-type']} #{response}")
  out('mock_requests_after_rejects', mock.stats[:requests])
  status, headers, response, = post({ 'x-api-key' => 'agent-test-key-2' }, body)
  out('api_key', "#{status} #{headers['x-mock-port'] || 'none'} #{response == MockLLM.answer_body(body, api: API)}")
  out('mock_requests', mock.stats[:requests])
end

def run_route(_mock)
  [['model_a', 'mock-model-a', { 'Authorization' => 'Bearer agent-test-key-1' }],
   ['model_b', 'mock-model-b', { 'x-api-key' => 'agent-test-key-2' }]].each do |key, model, credential|
    body = request_body(model)
    status, headers, response, = post(credential, body)
    out(key, "#{status} #{headers['x-mock-port'] || 'none'} #{headers['x-mock-authorization'] || 'none'} " \
             "#{headers['x-mock-x-api-key'] || 'none'} #{response == MockLLM.answer_body(body, api: API)}")
  end
  status, = post({ 'Authorization' => 'Bearer agent-test-key-1' }, request_body('other-model'))
  out('unknown_model', status)
end

def run_limit(mock)
  body = request_body('mock-model-a')
  held = Client.new(PORT, io_timeout: LIMIT)
  begin
    stream_body = request_body('mock-model-a', stream: true)
    status, headers, events, ending = held.stream('POST', PATH,
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

# The upstream errors of run_log, and the key of each in the output (529:
# overloaded, others: status_<code>).
LOG_ERRORS = { messages: [529], responses: [503, 429] }.freeze

def error_key(code)
  code == 529 ? 'overloaded' : "status_#{code}"
end

def run_log(_mock)
  body = request_body('mock-model-a')
  ok_id = "ok-#{API}-#{Process.pid}"
  status, = post({ 'Authorization' => 'Bearer agent-test-key-1', 'x-test-id' => ok_id }, body)
  out('ok', status)
  ids = LOG_ERRORS.fetch(API).map do |code|
    id = "#{error_key(code)}-#{API}-#{Process.pid}"
    status, headers, response, = post({ 'Authorization' => 'Bearer agent-test-key-1', 'x-test-id' => id,
                                        'x-mock-status' => code.to_s }, body)
    out(error_key(code), "#{status} #{headers['content-type']} #{response}")
    [code, id]
  end
  out('ok_log', log_line(ok_id))
  ids.each { |code, id| out("#{error_key(code)}_log", log_line(id)) }
end

# One stream per terminal event (for messages, the one stream of the API),
# printed as "<status> <Content-Type> <whether the body is the mock's
# stream byte for byte> <events>".
def run_stream(_mock)
  body = request_body('mock-model-a', stream: true)
  terminals = API == :responses ? MockLLM::TERMINALS : [nil]
  terminals.each do |terminal|
    headers = { 'Authorization' => 'Bearer agent-test-key-1' }
    headers['x-mock-terminal'] = terminal if terminal
    status, response_headers, response, = post(headers, body)
    expected = MockLLM.stream_body(body, api: API, terminal: terminal || MockLLM::DEFAULTS[:terminal])
    out(terminal ? "stream_#{terminal}" : 'stream',
        "#{status} #{response_headers['content-type']} #{response == expected} #{response.scan("\n\n").size}")
  end
end

mode = ARGV[0]
runner = { 'auth' => :run_auth, 'route' => :run_route, 'limit' => :run_limit, 'log' => :run_log,
           'stream' => :run_stream }[mode]
usage = "usage: ruby #{$PROGRAM_NAME} auth|route|limit|log|stream [messages|responses]"
abort usage unless runner && MockLLM::APIS.value?(API)

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
