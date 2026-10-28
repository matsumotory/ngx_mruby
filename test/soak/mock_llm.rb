# frozen_string_literal: true

# A mock LLM upstream (CRuby 3.0 or later) for the agent proxy scenarios of
# the memory soak test (test/soak/soak.rb), the performance comparison
# (test/perf/perf.rb) and the functional tests (test/t/cases/agent_proxy.rb).
# It speaks HTTP/1.1 and answers POST /v1/messages the way the Anthropic
# Messages API does and POST /v1/responses the way the OpenAI Responses API
# does, with output that depends only on the request and the options, so
# that a test can compare the response byte for byte.
#
#   ruby test/soak/mock_llm.rb --port 12362 [options]
#
# Options (the defaults in brackets):
#   --port PORT          listen on 127.0.0.1:PORT; repeat to listen on more
#                        ports, each one answering the same way. The
#                        response header x-mock-port names the port.
#   --events N           text delta events in a stream (content_block_delta,
#                        response.output_text.delta) [50]
#   --delta-text TEXT    the text of each text delta event ["hello "]
#   --hold-after K       write the first K events of a stream, then write
#                        nothing more and wait until the other side closes
#                        the connection [off]
#   --reset-after K      write the first K events of a stream, then reset
#                        the connection (RST) [off]
#   --status CODE        answer every POST with this status and an error
#                        body of its API, before any event [off]
#   --delay-ms MS        wait MS milliseconds between two events [0]
#   --one-write          write the head and the whole stream with one write
#                        instead of one write per event [off]
#   --terminal NAME      the event that ends a Responses stream:
#                        completed, incomplete or failed [completed]
#
# A request can override the options for itself with the headers
# x-mock-events, x-mock-hold-after, x-mock-reset-after, x-mock-status and
# x-mock-delay-ms, each a number of 0 or more, and x-mock-terminal, one of
# completed, incomplete and failed. x-mock-hold-after, x-mock-reset-after and
# x-mock-status also take "off", which turns the hold, the reset or the error
# status off. Any other value gets a 400 answer (invalid_request_error) that
# names the header. nginx forwards the headers to the upstream unless the
# configuration drops them.
# test/soak/mock_llm_test.rb checks these rules and the answers below.
#
# Answers of POST /v1/messages (Anthropic Messages API):
# - a JSON body whose "stream" is true: 200, Content-Type text/event-stream,
#   Transfer-Encoding chunked. The events are message_start (with usage),
#   content_block_start, N content_block_delta events with text,
#   content_block_stop, message_delta (with usage) and message_stop: N + 5
#   events.
# - without "stream": true: 200 with a message as JSON.
# Answers of POST /v1/responses (OpenAI Responses API; the event types and
# fields of openapi.yaml in github.com/openai/openai-openapi):
# - a JSON body whose "stream" is true: 200, text/event-stream, chunked. The
#   events are response.created and response.in_progress (with the Response
#   object in status in_progress), response.output_item.added,
#   response.content_part.added and N response.output_text.delta events,
#   each with a sequence_number from 0 up. Then, for --terminal completed or
#   incomplete: response.output_text.done, response.content_part.done,
#   response.output_item.done and response.completed or response.incomplete
#   (the whole Response object with its output and usage), N + 8 events; for
#   failed: response.failed (status failed, an error, usage null), N + 5
#   events.
# - without "stream": true: 200 with a Response object as JSON (status
#   completed).
# Both APIs:
# - Each event of a stream is one chunk and, without --one-write, one write;
#   the head goes with the first event and the last chunk with the last
#   event.
# - A body that is not a JSON object: 400 with an invalid_request_error in
#   the error format of the API.
# - GET /_mock/stats: the counters below as JSON.
# - Anything else: 404 with a not_found_error (Messages format).
# The usage in the answers is input_tokens = (request body bytes + 3) / 4 and
# output_tokens = N (6 for an answer without a stream). The model is the
# "model" of the request, or "mock-model". Responses carry x-mock-port and,
# when the request had them, x-mock-authorization and x-mock-x-api-key with
# the values that arrived, so that a test can see which credential the proxy
# sent.
#
# The mock never closes an idle keep-alive connection: it closes a connection
# only when the request asks for it (Connection: close, which the answer then
# carries as well), when the other side closes it, or for --hold-after and
# --reset-after. It never sleeps except for --delay-ms.
#
# Counters of GET /_mock/stats:
#   connections_open   connections open now, without the one asking
#   connections        connections accepted
#   requests           POST /v1/messages and POST /v1/responses requests read
#   completed          answers written in full (also error statuses)
#   held               streams waiting in --hold-after now
#   held_closed        streams in --hold-after that the other side closed
#   reset              connections reset by --reset-after
#   write_failed       answers that could not be written in full because the
#                      other side closed the connection

require 'io/wait'
require 'json'
require 'socket'

module MockLLM
  DEFAULTS = { events: 50, delta_text: 'hello ', hold_after: nil, reset_after: nil, status: nil,
               delay_ms: 0, one_write: false, terminal: 'completed' }.freeze
  # The paths of POST requests that the mock answers, and their API.
  APIS = { '/v1/messages' => :messages, '/v1/responses' => :responses }.freeze
  # The events that can end a Responses stream (--terminal, x-mock-terminal).
  TERMINALS = %w[completed incomplete failed].freeze
  MESSAGE_TEXT = 'Hello from the mock LLM.'
  MESSAGE_OUTPUT_TOKENS = 6
  ERROR_TYPES = { 400 => 'invalid_request_error', 401 => 'authentication_error', 403 => 'permission_error',
                  404 => 'not_found_error', 413 => 'request_too_large', 429 => 'rate_limit_error',
                  500 => 'api_error', 503 => 'api_error', 529 => 'overloaded_error' }.freeze
  # The error types of the Responses API's error body ({"error": {...}}):
  # those of the examples in openapi.yaml for 429 and 503, and
  # invalid_request_error or server_error for the other 4xx and 5xx statuses.
  RESPONSES_ERROR_TYPES = { 429 => 'rate_limit_error', 503 => 'service_unavailable_error' }.freeze
  # The fixed values of the Response objects: the ids of the response and of
  # its one output message, and created_at (completed_at is one second later).
  RESPONSE_ID = 'resp_mock'
  RESPONSE_ITEM_ID = 'msg_mock'
  RESPONSE_CREATED_AT = 1_760_000_000
  REASONS = { 200 => 'OK', 400 => 'Bad Request', 401 => 'Unauthorized', 403 => 'Forbidden', 404 => 'Not Found',
              413 => 'Payload Too Large', 429 => 'Too Many Requests', 500 => 'Internal Server Error',
              503 => 'Service Unavailable', 529 => 'Overloaded' }.freeze

  module_function

  def input_tokens(request_body)
    (request_body.bytesize + 3) / 4
  end

  def model_of(json)
    json.is_a?(Hash) && json['model'].is_a?(String) ? json['model'] : 'mock-model'
  end

  def sse(name, data)
    "event: #{name}\ndata: #{JSON.generate(data)}\n\n"
  end

  # The events of a stream, each a String that ends with an empty line.
  # terminal is used by the Responses API only.
  def stream_events(request_body, api: :messages, events: DEFAULTS[:events], delta_text: DEFAULTS[:delta_text],
                    terminal: DEFAULTS[:terminal])
    if api == :responses
      return responses_stream_events(request_body, events: events, delta_text: delta_text, terminal: terminal)
    end

    model = model_of(JSON.parse(request_body))
    usage_in = input_tokens(request_body)
    list = [
      sse('message_start', { type: 'message_start',
                             message: { id: 'msg_mock', type: 'message', role: 'assistant', model: model,
                                        content: [], stop_reason: nil, stop_sequence: nil,
                                        usage: { input_tokens: usage_in, output_tokens: 1 } } }),
      sse('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } })
    ]
    events.times do
      list << sse('content_block_delta', { type: 'content_block_delta', index: 0,
                                           delta: { type: 'text_delta', text: delta_text } })
    end
    list << sse('content_block_stop', { type: 'content_block_stop', index: 0 })
    list << sse('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: nil },
                                   usage: { output_tokens: events } })
    list << sse('message_stop', { type: 'message_stop' })
  end

  # The decoded body of a complete stream.
  def stream_body(request_body, **options)
    stream_events(request_body, **options).join
  end

  # The JSON body of an answer without "stream": true.
  def answer_body(request_body, api: :messages)
    api == :responses ? response_body(request_body) : message_body(request_body)
  end

  # The JSON body of a Messages answer without "stream": true.
  def message_body(request_body)
    JSON.generate({ id: 'msg_mock', type: 'message', role: 'assistant', model: model_of(JSON.parse(request_body)),
                    content: [{ type: 'text', text: MESSAGE_TEXT }], stop_reason: 'end_turn', stop_sequence: nil,
                    usage: { input_tokens: input_tokens(request_body), output_tokens: MESSAGE_OUTPUT_TOKENS } })
  end

  def error_body(status, message, api: :messages)
    return responses_error_body(status, message) if api == :responses

    JSON.generate({ type: 'error', error: { type: ERROR_TYPES.fetch(status, 'api_error'), message: message } })
  end

  # A request body of exactly size bytes whose user message is padded with
  # "x": a Messages request, or a Responses request with api: :responses.
  # "model" is the first key of the body.
  def request_body(size, model: 'mock-model', stream: false, api: :messages)
    head = { model: model, (api == :responses ? :max_output_tokens : :max_tokens) => 1024 }
    head[:stream] = true if stream
    list = api == :responses ? :input : :messages
    empty = JSON.generate(head.merge(list => [{ role: 'user', content: '' }]))
    raise ArgumentError, "a request body needs at least #{empty.bytesize} bytes" if size < empty.bytesize

    JSON.generate(head.merge(list => [{ role: 'user', content: 'x' * (size - empty.bytesize) }]))
  end

  # The Responses API (POST /v1/responses). The objects have the fields of
  # the schemas Response, ResponseUsage, OutputMessage and OutputTextContent
  # of openapi.yaml, in the order of its examples.

  def responses_usage(request_body, output_tokens)
    input = input_tokens(request_body)
    { input_tokens: input, input_tokens_details: { cached_tokens: 0, cache_write_tokens: 0 },
      output_tokens: output_tokens, output_tokens_details: { reasoning_tokens: 0 },
      total_tokens: input + output_tokens }
  end

  def responses_output_text(text)
    { type: 'output_text', text: text, annotations: [], logprobs: [] }
  end

  # The one output message of a response; no content while text is nil.
  def responses_output_message(status, text)
    { id: RESPONSE_ITEM_ID, type: 'message', status: status, role: 'assistant',
      content: text ? [responses_output_text(text)] : [] }
  end

  def response_object(model, status:, output: [], usage: nil, error: nil, incomplete_details: nil)
    { id: RESPONSE_ID, object: 'response', access_programs: nil, created_at: RESPONSE_CREATED_AT, status: status,
      completed_at: status == 'completed' ? RESPONSE_CREATED_AT + 1 : nil, error: error,
      incomplete_details: incomplete_details, instructions: nil, max_output_tokens: nil, model: model,
      output: output, parallel_tool_calls: true, previous_response_id: nil, store: false, temperature: 1,
      text: { format: { type: 'text' } }, tool_choice: 'auto', tools: [], top_p: 1, truncation: 'disabled',
      usage: usage, user: nil, metadata: {} }
  end

  # The events of a Responses stream (see the comment at the top for the
  # list). Each event's data has its type first and sequence_number last.
  def responses_stream_events(request_body, events: DEFAULTS[:events], delta_text: DEFAULTS[:delta_text],
                              terminal: DEFAULTS[:terminal])
    raise ArgumentError, "unknown terminal event #{terminal.inspect}" unless TERMINALS.include?(terminal)

    model = model_of(JSON.parse(request_body))
    text = delta_text * events
    sequence = -1
    event = lambda do |name, fields|
      sequence += 1
      sse(name, { type: name }.merge(fields).merge(sequence_number: sequence))
    end
    part = { item_id: RESPONSE_ITEM_ID, output_index: 0, content_index: 0 }
    in_progress = response_object(model, status: 'in_progress')
    list = [
      event.call('response.created', { response: in_progress }),
      event.call('response.in_progress', { response: in_progress }),
      event.call('response.output_item.added', { output_index: 0, item: responses_output_message('in_progress', nil) }),
      event.call('response.content_part.added', part.merge(part: responses_output_text('')))
    ]
    events.times { list << event.call('response.output_text.delta', part.merge(delta: delta_text, logprobs: [])) }
    if terminal == 'failed'
      error = { code: 'server_error', message: 'mock: the response failed' }
      return list << event.call('response.failed', { response: response_object(model, status: 'failed', error: error) })
    end

    item = responses_output_message(terminal, text)
    list << event.call('response.output_text.done', part.merge(text: text, logprobs: []))
    list << event.call('response.content_part.done', part.merge(part: responses_output_text(text)))
    list << event.call('response.output_item.done', { output_index: 0, item: item })
    details = terminal == 'incomplete' ? { reason: 'max_output_tokens' } : nil
    list << event.call("response.#{terminal}",
                       { response: response_object(model, status: terminal, output: [item],
                                                   usage: responses_usage(request_body, events),
                                                   incomplete_details: details) })
  end

  # The JSON body of a Responses answer without "stream": true.
  def response_body(request_body)
    JSON.generate(response_object(model_of(JSON.parse(request_body)), status: 'completed',
                                  output: [responses_output_message('completed', MESSAGE_TEXT)],
                                  usage: responses_usage(request_body, MESSAGE_OUTPUT_TOKENS)))
  end

  def responses_error_body(status, message)
    type = RESPONSES_ERROR_TYPES.fetch(status) { status < 500 ? 'invalid_request_error' : 'server_error' }
    JSON.generate({ error: { message: message, type: type, param: nil, code: nil } })
  end

  # Parses the command line options; returns [ports, options].
  def parse_args(argv)
    ports = []
    options = DEFAULTS.dup
    args = argv.dup
    until args.empty?
      flag = args.shift
      value = -> { args.shift or raise ArgumentError, "#{flag} needs a value" }
      case flag
      when '--port' then ports << Integer(value.call, 10)
      when '--events' then options[:events] = Integer(value.call, 10)
      when '--delta-text' then options[:delta_text] = value.call
      when '--hold-after' then options[:hold_after] = Integer(value.call, 10)
      when '--reset-after' then options[:reset_after] = Integer(value.call, 10)
      when '--status' then options[:status] = Integer(value.call, 10)
      when '--delay-ms' then options[:delay_ms] = Integer(value.call, 10)
      when '--one-write' then options[:one_write] = true
      when '--terminal'
        options[:terminal] = value.call
        raise ArgumentError, "--terminal must be one of #{TERMINALS.join(', ')}" unless TERMINALS.include?(options[:terminal])
      else raise ArgumentError, "unknown option #{flag}"
      end
    end
    raise ArgumentError, 'at least one --port is needed' if ports.empty?

    [ports, options]
  end

  # The server. start listens on every port and serves each connection in a
  # thread of its own; stop closes the listening sockets and the connections.
  class Server
    COUNTERS = %i[connections requests completed held held_closed reset write_failed].freeze
    # The request headers that override an option with a number, those of
    # them that also take "off" (no hold, no reset, no error status), and the
    # header that names the terminal event of a Responses stream.
    OVERRIDE_HEADERS = { 'x-mock-events' => :events, 'x-mock-hold-after' => :hold_after,
                         'x-mock-reset-after' => :reset_after, 'x-mock-status' => :status,
                         'x-mock-delay-ms' => :delay_ms }.freeze
    OFF_HEADERS = %w[x-mock-hold-after x-mock-reset-after x-mock-status].freeze
    TERMINAL_HEADER = 'x-mock-terminal'

    def initialize(ports, **options)
      @ports = ports
      @options = DEFAULTS.merge(options)
      @lock = Mutex.new
      @counts = COUNTERS.to_h { |k| [k, 0] }
      @open = {}
      @listeners = []
      @threads = []
    end

    def start
      @ports.each do |port|
        server = TCPServer.new('127.0.0.1', port)
        @listeners << server
        @threads << Thread.new { accept_loop(server, port) }
      end
      self
    end

    def stop
      @listeners.each { |s| s.close unless s.closed? }
      @lock.synchronize { @open.keys }.each { |s| s.close unless s.closed? }
      @threads.each { |t| t.join(5) }
    end

    # The counters, with connections_open less the connection given.
    def stats(except = nil)
      @lock.synchronize do
        @counts.merge(connections_open: @open.size - (except && @open.key?(except) ? 1 : 0))
      end
    end

    private

    def count(key, by = 1)
      @lock.synchronize { @counts[key] += by }
    end

    def accept_loop(server, port)
      loop do
        sock = server.accept
        sock.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
        @lock.synchronize do
          @open[sock] = true
          @counts[:connections] += 1
        end
        Thread.new { serve(sock, port) }
      end
    rescue IOError, SystemCallError
      nil # the listening socket was closed by stop
    end

    def serve(sock, port)
      buf = String.new(encoding: Encoding::BINARY)
      loop do
        req = read_request(sock, buf)
        break unless req

        closing = req[:headers]['connection'].to_s.downcase == 'close'
        break unless answer(sock, port, req, closing)
        break if closing
      end
    rescue IOError, SystemCallError
      nil
    ensure
      @lock.synchronize { @open.delete(sock) }
      sock.close unless sock.closed?
    end

    # Returns { method:, path:, headers:, body: }, or nil at EOF before a request.
    def read_request(sock, buf)
      until (idx = buf.index("\r\n\r\n"))
        return nil unless fill(sock, buf)
      end
      lines = buf.slice!(0, idx + 4).split("\r\n")
      method, path, = lines.shift.to_s.split(' ', 3)
      headers = {}
      lines.each do |line|
        key, value = line.split(':', 2)
        headers[key.strip.downcase] = value.to_s.strip
      end
      body = if headers['transfer-encoding'].to_s.downcase.include?('chunked')
               read_chunked(sock, buf)
             else
               take(sock, buf, headers.fetch('content-length', '0').to_i)
             end
      { method: method, path: path, headers: headers, body: body }
    end

    def fill(sock, buf)
      buf << sock.readpartial(65_536)
      true
    rescue EOFError
      false
    end

    def take(sock, buf, size)
      while buf.bytesize < size
        raise EOFError, 'connection closed in a request body' unless fill(sock, buf)
      end
      buf.slice!(0, size)
    end

    def take_line(sock, buf)
      until (idx = buf.index("\r\n"))
        raise EOFError, 'connection closed in a request body' unless fill(sock, buf)
      end
      buf.slice!(0, idx + 2).chomp("\r\n")
    end

    def read_chunked(sock, buf)
      body = String.new(encoding: Encoding::BINARY)
      loop do
        size = take_line(sock, buf).split(';', 2).first.to_i(16)
        if size.zero?
          nil until take_line(sock, buf).empty?
          return body
        end
        body << take(sock, buf, size)
        take_line(sock, buf)
      end
    end

    # Writes the answer. Returns false when the connection must not be used
    # again.
    def answer(sock, port, req, closing)
      extra = { 'x-mock-port' => port.to_s }
      extra['Connection'] = 'close' if closing
      extra['x-mock-authorization'] = req[:headers]['authorization'] if req[:headers].key?('authorization')
      extra['x-mock-x-api-key'] = req[:headers]['x-api-key'] if req[:headers].key?('x-api-key')

      if req[:method] == 'GET' && req[:path] == '/_mock/stats'
        return write_full(sock, head(200, 'application/json', extra, JSON.generate(stats(sock))), counted: false)
      end
      api = req[:method] == 'POST' && APIS[req[:path]]
      unless api
        return write_full(sock, head(404, 'application/json', extra, MockLLM.error_body(404, 'mock: no such path')),
                          counted: false)
      end

      count(:requests)
      opts, bad_header = request_options(req[:headers])
      if bad_header
        return write_full(sock, head(400, 'application/json', extra, MockLLM.error_body(400, bad_header, api: api)))
      end

      json = begin
        JSON.parse(req[:body])
      rescue JSON::ParserError
        nil
      end
      unless json.is_a?(Hash)
        return write_full(sock, head(400, 'application/json', extra,
                                     MockLLM.error_body(400, 'mock: the body is not a JSON object', api: api)))
      end
      if opts[:status]
        status = opts[:status]
        return write_full(sock, head(status, 'application/json', extra,
                                     MockLLM.error_body(status, "mock: status #{status}", api: api)))
      end
      unless json['stream'] == true
        return write_full(sock, head(200, 'application/json', extra, MockLLM.answer_body(req[:body], api: api)))
      end

      write_stream(sock, extra, req[:body], opts, api)
    end

    # The options of one request: the server's, overridden by the x-mock-*
    # headers. Returns [options, nil], or [nil, message] for a header whose
    # value is not a number of 0 or more (or "off" where OFF_HEADERS allow it,
    # or one of TERMINALS for TERMINAL_HEADER).
    def request_options(headers)
      opts = @options.dup
      if headers.key?(TERMINAL_HEADER)
        value = headers[TERMINAL_HEADER]
        unless TERMINALS.include?(value)
          return [nil, "mock: #{TERMINAL_HEADER} must be one of #{TERMINALS.join(', ')}, not #{value.inspect}"]
        end

        opts[:terminal] = value
      end
      OVERRIDE_HEADERS.each do |name, key|
        next unless headers.key?(name)

        value = headers[name]
        if value == 'off' && OFF_HEADERS.include?(name)
          opts[key] = nil
        elsif value.match?(/\A\d+\z/)
          opts[key] = Integer(value, 10)
        else
          allowed = OFF_HEADERS.include?(name) ? 'a number of 0 or more, or off' : 'a number of 0 or more'
          return [nil, "mock: #{name} must be #{allowed}, not #{value.inspect}"]
        end
      end
      [opts, nil]
    end

    def head(status, type, extra, body = nil)
      lines = ["HTTP/1.1 #{status} #{REASONS.fetch(status, 'Status')}", "Content-Type: #{type}"]
      lines << (body ? "Content-Length: #{body.bytesize}" : 'Transfer-Encoding: chunked')
      lines << 'Cache-Control: no-cache' unless body
      extra.each { |k, v| lines << "#{k}: #{v}" }
      "#{lines.join("\r\n")}\r\n\r\n#{body}"
    end

    def write_full(sock, data, counted: true)
      sock.write(data)
      count(:completed) if counted
      true
    rescue IOError, SystemCallError
      count(:write_failed) if counted
      false
    end

    def chunk(data)
      "#{data.bytesize.to_s(16)}\r\n#{data}\r\n"
    end

    def write_stream(sock, extra, request_body, opts, api)
      events = MockLLM.stream_events(request_body, api: api, events: opts[:events], delta_text: opts[:delta_text],
                                                   terminal: opts[:terminal])
      stop_at = [opts[:hold_after], opts[:reset_after]].compact.min
      cut = stop_at && stop_at < events.size
      writes = (cut ? events.first(stop_at) : events).map { |e| chunk(e) }
      writes[0] = head(200, 'text/event-stream', extra) + writes[0].to_s
      writes[-1] += "0\r\n\r\n" unless cut
      writes = [writes.join] if opts[:one_write]
      writes.each_with_index do |data, i|
        sleep(opts[:delay_ms] / 1000.0) if i.positive? && opts[:delay_ms].positive?
        sock.write(data)
      end
      unless cut
        count(:completed)
        return true
      end

      if opts[:reset_after] && opts[:reset_after] == stop_at
        sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack('ii'))
        sock.close
        count(:reset)
      else
        hold(sock)
      end
      false
    rescue IOError, SystemCallError
      count(:write_failed)
      false
    end

    # Waits until the other side closes the connection; reads and drops
    # whatever arrives meanwhile.
    def hold(sock)
      count(:held)
      begin
        loop { sock.readpartial(65_536) }
      rescue EOFError, IOError, SystemCallError
        nil
      end
      @lock.synchronize do
        @counts[:held] -= 1
        @counts[:held_closed] += 1
      end
    end
  end
end

module MockLLM
  # The mock as a child process, for the drivers (soak.rb, perf.rb): start
  # runs this file with --port port and the options, with its output in log;
  # stats reads GET /_mock/stats; stop sends SIGTERM. Errors raise
  # MockLLM::Child::Error.
  class Child
    class Error < StandardError; end

    def initialize(port, options, log)
      @port = port
      @options = options
      @log = log
    end

    def start(timeout)
      @pid = Process.spawn('ruby', __FILE__, '--port', @port.to_s, *@options, %i[out err] => [@log, 'w'])
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
      loop do
        raise Error, "the mock LLM exited at startup:\n#{File.read(@log)}" if Process.waitpid(@pid, Process::WNOHANG)

        begin
          Socket.tcp('127.0.0.1', @port, connect_timeout: 1).close
          return
        rescue SystemCallError
          raise Error, "the mock LLM is not listening on #{@port} after #{timeout} s" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
        end
        sleep 0.05
      end
    end

    # The counters of GET /_mock/stats, with symbols as keys.
    def stats(timeout = 30)
      Socket.tcp('127.0.0.1', @port, connect_timeout: 5) do |sock|
        sock.write("GET /_mock/stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        raw = String.new(encoding: Encoding::BINARY)
        loop do
          raise Error, "no answer from the mock LLM within #{timeout} s" unless sock.wait_readable(timeout)

          chunk = sock.read_nonblock(65_536, exception: false)
          break if chunk.nil?

          raw << chunk unless chunk == :wait_readable
        end
        head, body = raw.split("\r\n\r\n", 2)
        raise Error, "the mock LLM's /_mock/stats answered #{head.to_s.lines.first.inspect}" unless head.to_s.start_with?('HTTP/1.1 200')

        JSON.parse(body, symbolize_names: true)
      end
    end

    # Stops the mock. Returns a list of problems (empty when none).
    def stop(timeout)
      return [] unless @pid

      Process.kill(:TERM, @pid)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
      exited = nil
      sleep 0.05 until (exited = Process.waitpid(@pid, Process::WNOHANG)) || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      problems = []
      unless exited
        problems << "the mock LLM did not exit within #{timeout} s of SIGTERM; killed"
        Process.kill(:KILL, @pid)
        Process.wait(@pid)
      end
      @pid = nil
      problems
    rescue Errno::ESRCH, Errno::ECHILD
      @pid = nil
      []
    end
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    ports, options = MockLLM.parse_args(ARGV)
  rescue ArgumentError => e
    abort "mock_llm: #{e.message}"
  end
  Thread.report_on_exception = false
  server = MockLLM::Server.new(ports, **options).start
  $stdout.puts "mock_llm: listening on #{ports.map { |p| "127.0.0.1:#{p}" }.join(', ')}"
  $stdout.flush
  done = Queue.new
  %w[TERM INT].each { |sig| Signal.trap(sig) { done << sig } }
  done.pop
  server.stop
end
