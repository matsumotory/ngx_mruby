# frozen_string_literal: true

# Checks of the mock LLM upstream test/soak/mock_llm.rb (CRuby 3.0 or
# later): runs MockLLM::Server in this process on a free port of 127.0.0.1,
# sends requests with test/soak/http_client.rb and compares the answers and
# the counters with what the mock's comment and docs/test/README.md say.
# Needs no nginx; takes about a second. test/soak/run.sh runs it before the
# soak. Exits with 1 when a check fails.
#
#   ruby test/soak/mock_llm_test.rb

require 'socket'
require_relative 'mock_llm'
require_relative 'http_client'

def free_port
  server = TCPServer.new('127.0.0.1', 0)
  server.addr[1]
ensure
  server&.close
end

FAILURES = []

def check(name, got, expected)
  FAILURES << "#{name}: got #{got.inspect}, expected #{expected.inspect}" unless got == expected
end

def post(port, headers, body)
  client = Client.new(port, io_timeout: 10)
  client.request('POST', '/v1/messages', headers, body, close: true)
rescue EOFError, Client::Timeout, SystemCallError => e
  [e.class.name, {}, '', false]
ensure
  client&.close
end

def stream(port, headers, body, &stop)
  client = Client.new(port, io_timeout: 10)
  status, _headers, received, ending = client.stream('POST', '/v1/messages', headers, body, &stop)
  [status, received, ending]
ensure
  client&.close
end

def wait_for(server, key, value)
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
  sleep 0.01 until server.stats[key] == value || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
  server.stats[key]
end

Thread.report_on_exception = false
port = free_port
# Streams of 3 deltas (8 events); every stream is held after 2 events unless
# the request says otherwise.
server = MockLLM::Server.new([port], events: 3, hold_after: 2).start
body = MockLLM.request_body(300, model: 'mock-model-a', stream: true)
message = MockLLM.request_body(300, model: 'mock-model-a')
events = MockLLM.stream_events(body, events: 3)
sent = 0
begin
  status, headers, answer, = post(port, { 'Authorization' => 'Bearer k' }, message)
  sent += 1
  check('message', [status, headers['content-type'], answer], [200, 'application/json', MockLLM.message_body(message)])
  check('message echo of Authorization', [headers['x-mock-port'], headers['x-mock-authorization']], [port.to_s, 'Bearer k'])

  status, answer, ending = stream(port, {}, body) { |b| b.scan("\n\n").size >= 2 }
  sent += 1
  check('stream held after 2 events', [status, answer, ending], [200, events.first(2).join, :stopped])
  check('held stream closed by the client', wait_for(server, :held_closed, 1), 1)

  %w[0 1].each do |value|
    status, _headers, answer, = post(port, { 'x-mock-hold-after' => 'off', 'x-mock-delay-ms' => value }, body)
    sent += 1
    check("x-mock-hold-after: off, x-mock-delay-ms: #{value}", [status, answer], [200, events.join])
  end

  status, _headers, answer, = post(port, { 'x-mock-hold-after' => 'off', 'x-mock-events' => '1' }, body)
  sent += 1
  check('x-mock-events: 1', [status, answer], [200, MockLLM.stream_body(body, events: 1)])

  status, answer, ending = stream(port, { 'x-mock-hold-after' => 'off', 'x-mock-reset-after' => '2' }, body) { false }
  sent += 1
  check('x-mock-reset-after: 2', [status, answer, ending], [200, events.first(2).join, :reset])

  status, _headers, answer, = post(port, { 'x-mock-status' => '529' }, body)
  sent += 1
  check('x-mock-status: 529', [status, answer], [529, MockLLM.error_body(529, 'mock: status 529')])

  # Only x-mock-hold-after, x-mock-reset-after and x-mock-status take "off";
  # the other headers and values that are not numbers get a 400 answer.
  %w[x-mock-delay-ms x-mock-events].each do |name|
    ['off', 'abc', '-1'].each do |value|
      status, headers, answer, = post(port, { 'x-mock-hold-after' => 'off', name => value }, body)
      sent += 1
      check("#{name}: #{value}", [status, headers['content-type'], JSON.parse(answer)['error']['type']],
            [400, 'application/json', 'invalid_request_error'])
    rescue JSON::ParserError, NoMethodError
      check("#{name}: #{value}", [status, answer], [400, 'an invalid_request_error body'])
    end
  end

  stats = server.stats
  check('requests counted', stats[:requests], sent)
  check('answers written in full', stats[:completed], sent - 2)
  check('resets', stats[:reset], 1)
  check('streams held now', stats[:held], 0)
  check('failed writes', stats[:write_failed], 0)
  check('open connections', wait_for(server, :connections_open, 0), 0)
ensure
  server.stop
end

FAILURES.each { |f| warn "mock_llm_test: #{f}" }
puts "mock_llm_test: #{FAILURES.empty? ? 'ok' : "#{FAILURES.size} failed"}"
exit(FAILURES.empty? ? 0 : 1)
