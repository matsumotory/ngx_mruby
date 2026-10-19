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

def post(port, headers, body, path = '/v1/messages')
  client = Client.new(port, io_timeout: 10)
  client.request('POST', path, headers, body, close: true)
rescue EOFError, Client::Timeout, SystemCallError => e
  [e.class.name, {}, '', false]
ensure
  client&.close
end

def stream(port, headers, body, path = '/v1/messages', &stop)
  client = Client.new(port, io_timeout: 10)
  status, _headers, received, ending = client.stream('POST', path, headers, body, &stop)
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
  messages_stats = stats
  messages_sent = sent

  # The Responses API on /v1/responses: the same options, its own events,
  # bodies and error format.
  r_path = '/v1/responses'
  r_body = MockLLM.request_body(300, model: 'mock-model-a', stream: true, api: :responses)
  r_message = MockLLM.request_body(300, model: 'mock-model-a', api: :responses)
  check('Responses request body: size and first key', [r_body.bytesize, JSON.parse(r_body).keys.first, JSON.parse(r_body).key?('input')],
        [300, 'model', true])
  status, headers, answer, = post(port, {}, r_message, r_path)
  sent += 1
  check('Responses: answer without a stream', [status, headers['content-type'], answer],
        [200, 'application/json', MockLLM.response_body(r_message)])
  response = JSON.parse(answer)
  check('Responses: the Response object', [response['object'], response['status'], response['model'],
                                           response['output'][0]['content'][0]['text'], response['usage']['output_tokens'],
                                           response['usage']['total_tokens']],
        ['response', 'completed', 'mock-model-a', MockLLM::MESSAGE_TEXT, 6, MockLLM.input_tokens(r_message) + 6])

  { 'completed' => 3 + 8, 'incomplete' => 3 + 8, 'failed' => 3 + 5 }.each do |terminal, count|
    status, headers, answer, = post(port, { 'x-mock-hold-after' => 'off', 'x-mock-terminal' => terminal }, r_body, r_path)
    sent += 1
    expected = MockLLM.stream_events(r_body, api: :responses, events: 3, terminal: terminal)
    check("Responses: x-mock-terminal: #{terminal}", [status, headers['content-type'], answer, expected.size],
          [200, 'text/event-stream', expected.join, count])
    # Each event: "event: <type>" and data whose type is the same, with
    # sequence_number counting from 0.
    parsed = answer.split("\n\n").map do |e|
      name, data = e.split("\n", 2)
      [name.delete_prefix('event: '), JSON.parse(data.delete_prefix('data: '))]
    end
    check("Responses: #{terminal}: event names and sequence numbers",
          parsed.map { |name, data| [name == data['type'], data['sequence_number']] },
          (0...count).map { |i| [true, i] })
    check("Responses: #{terminal}: the first and the last event", [parsed.first[0], parsed.last[0]],
          ['response.created', "response.#{terminal}"])
    check("Responses: #{terminal}: deltas", parsed.count { |name, _| name == 'response.output_text.delta' }, 3)
    last = parsed.last[1]['response']
    usage = terminal == 'failed' ? nil : { 'input_tokens' => MockLLM.input_tokens(r_body),
                                           'input_tokens_details' => { 'cached_tokens' => 0, 'cache_write_tokens' => 0 },
                                           'output_tokens' => 3, 'output_tokens_details' => { 'reasoning_tokens' => 0 },
                                           'total_tokens' => MockLLM.input_tokens(r_body) + 3 }
    check("Responses: #{terminal}: status and usage of the last event", [last['status'], last['usage']], [terminal, usage])
  end

  status, answer, ending = stream(port, {}, r_body, r_path) { |b| b.scan("\n\n").size >= 2 }
  sent += 1
  check('Responses: stream held after 2 events', [status, answer, ending],
        [200, MockLLM.stream_events(r_body, api: :responses, events: 3).first(2).join, :stopped])
  check('Responses: held stream closed by the client', wait_for(server, :held_closed, 2), 2)

  status, answer, ending = stream(port, { 'x-mock-hold-after' => 'off', 'x-mock-reset-after' => '4' }, r_body, r_path) { false }
  sent += 1
  check('Responses: x-mock-reset-after: 4', [status, answer, ending],
        [200, MockLLM.stream_events(r_body, api: :responses, events: 3).first(4).join, :reset])

  [503, 429, 400, 500].each do |code|
    status, _headers, answer, = post(port, { 'x-mock-status' => code.to_s }, r_body, r_path)
    sent += 1
    check("Responses: x-mock-status: #{code}", [status, answer],
          [code, MockLLM.responses_error_body(code, "mock: status #{code}")])
  end
  check('Responses: error types', [503, 429, 400, 500].map { |c| JSON.parse(MockLLM.responses_error_body(c, 'm'))['error']['type'] },
        %w[service_unavailable_error rate_limit_error invalid_request_error server_error])

  %w[done COMPLETED 1].each do |value|
    status, _headers, answer, = post(port, { 'x-mock-hold-after' => 'off', 'x-mock-terminal' => value }, r_body, r_path)
    sent += 1
    message = "mock: x-mock-terminal must be one of completed, incomplete, failed, not #{value.inspect}"
    check("Responses: x-mock-terminal: #{value}", [status, answer], [400, MockLLM.responses_error_body(400, message)])
  end

  status, _headers, answer, = post(port, {}, 'not json', r_path)
  sent += 1
  check('Responses: a body that is not JSON', [status, answer],
        [400, MockLLM.responses_error_body(400, 'mock: the body is not a JSON object')])
  check('Responses: the error body', JSON.parse(MockLLM.responses_error_body(400, 'm')),
        { 'error' => { 'message' => 'm', 'type' => 'invalid_request_error', 'param' => nil, 'code' => nil } })

  check('--terminal on the command line', MockLLM.parse_args(%w[--port 1 --terminal failed]), [[1], MockLLM::DEFAULTS.merge(terminal: 'failed')])
  begin
    MockLLM.parse_args(%w[--port 1 --terminal done])
    check('--terminal done', 'accepted', 'ArgumentError')
  rescue ArgumentError
    nil
  end

  # The counters of the Responses requests: the differences from the
  # counters after the Messages requests.
  stats = server.stats
  check('Responses: requests counted', stats[:requests] - messages_stats[:requests], sent - messages_sent)
  check('Responses: answers written in full', stats[:completed] - messages_stats[:completed], sent - messages_sent - 2)
  check('Responses: resets', stats[:reset] - messages_stats[:reset], 1)
  check('Responses: streams held now', stats[:held], 0)
  check('Responses: failed writes', stats[:write_failed] - messages_stats[:write_failed], 0)
  check('Responses: open connections', wait_for(server, :connections_open, 0), 0)
ensure
  server.stop
end

FAILURES.each { |f| warn "mock_llm_test: #{f}" }
puts "mock_llm_test: #{FAILURES.empty? ? 'ok' : "#{FAILURES.size} failed"}"
exit(FAILURES.empty? ? 0 : 1)
