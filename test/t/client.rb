# frozen_string_literal: false

# The test client of test/t/ngx_mruby.rb and test/t/cases/*.rb, in CRuby.
# test.sh loads this file with `ruby -r` before each test file. It defines
# the classes and methods that the tests took from the test build of mruby
# before, with the same requests and the same results:
#
# - HttpRequest and SimpleHttp, as in matsumotory/mruby-httprequest and
#   matsumotory/mruby-simplehttp built with NO_SSL: one HTTP/1.0 request per
#   connection with "Connection: close", the header names capitalized
#   ("Content-type") and sorted, "Host" and "Accept: */*" added, and the
#   response read until the server closes the connection. The response is
#   parsed in the same way, so res["body"], res["code"], res.headers and the
#   lower-case header keys mean what they meant.
# - SimpleTest, as in matsumotory/mruby-simpletest: the assertions and
#   skip, their messages and the report, which raises when a test failed or crashed, so
#   that the test file exits non-zero.
# - Kernel#usleep, as in mruby-sleep.
# - JSON and TCPSocket, from the standard library.
#
# The test files run with binary source and external encodings (test.sh
# passes -E ASCII-8BIT, and the test files start with a magic comment), so
# that strings are byte strings, as in the test build of mruby, which has no
# MRB_UTF8_STRING.

require 'json'
require 'socket'

def usleep(usec)
  sleep(usec / 1_000_000.0)
end

class HttpRequest
  # scheme://[userinfo@]host[:port][path][?query][#fragment], as the URL
  # parser of mattn/mruby-http reads it.
  URL = %r{\A([A-Za-z][A-Za-z0-9+.-]*)://(?:[^@/?#]*@)?(\[[^\]]*\]|[^:/?#\[\]]*)(?::([0-9]+))?([^?#]*)(?:\?([^#]*))?(?:#.*)?\z}m.freeze

  def get(url, body = nil, headers = {}, &b)
    request('GET', url, body, headers, &b)
  end

  def head(url, headers = {}, &b)
    request('HEAD', url, nil, headers, &b)
  end

  def post(url, body = nil, headers = {}, &b)
    request('POST', url, body, headers, &b)
  end

  def put(url, body = nil, headers = {}, &b)
    request('PUT', url, body, headers, &b)
  end

  def delete(url, headers = {}, &b)
    request('DELETE', url, nil, headers, &b)
  end

  # Bytes that the URL parser of mattn/mruby-http rejects: controls, the
  # space, DEL and bytes that are not ASCII.
  NOT_URL = /[\x00-\x20\x7f-\xff]/n.freeze

  def request(method, url, body, headers, &b)
    url = url.to_s.b
    m = URL.match(url)
    raise ArgumentError, 'invalid URL' if m.nil? || NOT_URL.match?(url)

    host = m[2].delete_prefix('[').delete_suffix(']')
    # Without a port, mruby-http gives 443 for https and nothing otherwise,
    # and SimpleHttp then takes 80.
    port = m[3] ? Integer(m[3], 10) : (m[1] == 'https' ? 443 : nil)
    path = m[4].empty? ? nil : m[4]
    query = m[5].nil? || m[5].empty? ? nil : m[5]
    request = create_http_request(method, body, headers)
    request_uri = query ? path + '?' + query : path
    SimpleHttp.new(m[1], host, port).request(method, request_uri, request, &b)
  end

  def encode_parameters(params, delimiter = '&', quote = nil)
    if params.is_a?(Hash)
      params = params.map do |key, value|
        format('%s=%s%s%s', escape(key), quote, escape(value), quote)
      end
    else
      params = params.map { |value| escape(value) }
    end
    delimiter ? params.join(delimiter) : params
  end

  # The headers Hash of the caller gets "body" and "Content-Length", as in
  # mruby-httprequest.
  def create_http_request(method, body, headers)
    method = method.upcase.to_s
    request = headers
    if %w[POST PUT GET].include?(method) && body
      request['body'] = body.is_a?(Hash) ? encode_parameters(body) : body.to_s
      request['Content-Length'] = (request['body'] || '').bytesize
    end
    request
  end

  UNRESERVED = (('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a + %w[- . _ ~]).freeze

  def escape(str)
    str.to_s.b.each_char.map { |chr| UNRESERVED.include?(chr) ? chr : '%' + chr.unpack1('H*').upcase }.join
  end
end

class SimpleHttp
  DEFAULTPORT = 80
  HTTP_VERSION = 'HTTP/1.0'.freeze
  DEFAULT_ACCEPT = '*/*'.freeze
  SEP = "\r\n".freeze
  READ_BUF_SIZE = ENV['READ_BUF_SIZE'] || ENV['BUF_SIZE'] || 4096
  WRITE_BUF_SIZE = ENV['WRITE_BUF_SIZE'] || ENV['BUF_SIZE'] || 4096

  # Without HTTPS (NO_SSL), an https URL is sent in plain text, to its port
  # (443 when the URL has none), as the test build of mruby-simplehttp did.
  def initialize(scheme, address, port = nil)
    @uri = { scheme: scheme }
    if scheme == 'unix'
      @uri[:file] = address
    else
      @uri[:address] = address
      @uri[:port] = port ? port.to_i : DEFAULTPORT
    end
  end

  def address
    @uri[:address]
  end

  def port
    @uri[:port]
  end

  def get(path = '/', req = nil, &b)
    request('GET', path, req, &b)
  end

  def post(path = '/', req = nil)
    request('POST', path, req)
  end

  def put(path = '/', req = nil)
    request('PUT', path, req)
  end

  def request(method, path, req, &b)
    @uri[:path] = path
    if @uri[:path].nil?
      @uri[:path] = '/'
    elsif @uri[:path][0] != '/'
      @uri[:path] = '/' + @uri[:path]
    end
    request_header = create_request_header(method.upcase.to_s, req)
    response_text = send_request(request_header, &b)
    SimpleHttpResponse.new(response_text)
  end

  # Writes the request and reads the response until the server closes the
  # connection, without a timeout. With a block, each part read goes to the
  # block instead of the response.
  def send_request(request_header)
    response_text = String.new(encoding: Encoding::BINARY)
    socket = if @uri[:scheme] == 'unix'
               UNIXSocket.open(@uri[:file])
             else
               TCPSocket.new(@uri[:address], @uri[:port])
             end
    begin
      slice_by_buffer_size(request_header).each { |str| socket.write(str) }
      while (t = socket.read(READ_BUF_SIZE.to_i))
        if block_given?
          yield t
          next
        end
        response_text << t
      end
    ensure
      socket.close
    end
    response_text
  end

  def create_request_header(method, req)
    req ||= {}
    str = String.new(encoding: Encoding::BINARY)
    body = ''
    str << format('%s %s %s', method, @uri[:path], HTTP_VERSION).b + SEP
    header = {}
    req.each do |key, value|
      name = key.capitalize
      if !header[name].nil?
        if header[name].is_a?(Array)
          header[name] << value
        else
          header[name] = [header[name], value]
        end
      else
        header[name] = value
      end
    end
    header['Host'] = @uri[:address] unless header.key?('Host')
    header['Accept'] = DEFAULT_ACCEPT unless header.key?('Accept')
    header['Connection'] = 'close'
    if header['Body']
      body = header['Body']
      header.delete('Body')
    end
    if %w[POST PUT].include?(method) && !header.key?('Content-length')
      header['Content-Length'] = (body || '').bytesize
    end
    header.keys.sort.each do |key|
      str << format('%s: %s', key, header[key]).b + SEP
    end
    str + SEP + body.to_s.b
  end

  def slice_by_buffer_size(str, buffer_size = WRITE_BUF_SIZE)
    buffer_size = buffer_size.to_i
    (1..(str.bytesize / buffer_size + 1)).map do |i|
      str.byteslice(((i - 1) * buffer_size)...(i * buffer_size))
    end
  end

  class SimpleHttpResponse
    SEP = SimpleHttp::SEP

    def initialize(response_text)
      @response = {}
      @headers = {}
      if response_text.empty?
        @response['header'] = nil
      elsif response_text.include?(SEP + SEP)
        @response['header'], @response['body'] = response_text.split(SEP + SEP, 2)
      else
        @response['header'] = response_text
      end
      parse_header
    end

    def [](key)
      @response[key]
    end

    def []=(key, value)
      @response[key] = value
    end

    def header
      @response['header']
    end

    attr_reader :headers

    def body
      @response['body']
    end

    def status
      @response['status']
    end

    def code
      @response['code']
    end

    def date
      @response['date']
    end

    def content_type
      @response['content-type']
    end

    def content_length
      @response['content-length']
    end

    def each(&block)
      @response.each { |k, v| block.call(k, v) } if block
    end

    def each_name(&block)
      @response.each { |k, _| block.call(k) } if block
    end

    private

    # Each line with ": " is a header: its name in lower case is the key, and
    # the text between the first and the second ": " is the value. A name
    # that comes again gets an Array of its values.
    def parse_header
      return unless @response['header']

      h = @response['header'].split(SEP)
      if h[0].include?('HTTP/1')
        @response['status'] = h[0].split(' ', 2).last
        @response['code'] = h[0].split(' ', 3)[1].to_i
      end
      h.each do |line|
        next unless line.include?(': ')

        k, v = line.split(': ')
        key = k.downcase
        if !@response[key].nil?
          if @response[key].is_a?(Array)
            @response[key] << v
            @headers[key] << v
          else
            @response[key] = [@response[key], v]
            @headers[key] = [@headers[key], v]
          end
        else
          @response[key] = v
          @headers[key] = v
        end
      end
    end
  end
end

class SimpleTest
  def initialize(title = nil)
    @ok_test = 0
    @ko_test = 0
    @kill_test = 0
    @asserts = []
    @test_start = Time.now
    t_print("SimpleTest: #{title}\n") unless title.nil?
  end

  def t_print(*args)
    args.each { |arg| $stdout.print arg.to_s }
    $stdout.flush
  end

  def assertion_string(err, str, iso = nil, e = nil)
    msg = "#{err}#{str}"
    msg += " [#{iso}]" if iso && iso != ''
    msg += " => #{e.message}" if e
    if @mrbtest_assert && !@mrbtest_assert.empty?
      @mrbtest_assert.each do |idx, s, diff|
        msg += "\n - Assertion[#{idx}] Failed: #{s}\n#{diff}"
      end
    end
    msg
  end

  # Runs the block as one test. The test fails when the block returns false
  # or nil, or when an assertion inside it failed, and crashes when the block
  # raises. The gem compares the class name of the exception with
  # 'MRubyTestSkip', which the nested class SimpleTest::MRubyTestSkip never
  # has, so a test that calls skip counts as crashed there and here.
  def assert(str = 'Assertion failed', iso = '')
    @mrbtest_assert = []
    @mrbtest_assert_idx = 0
    if !yield || !@mrbtest_assert.empty?
      @asserts.push(assertion_string('Fail: ', str, iso, nil))
      @ko_test += 1
      t_print('F')
    else
      @ok_test += 1
      t_print('.')
    end
  rescue Exception => e # rubocop:disable Lint/RescueException
    if e.class.to_s == 'MRubyTestSkip'
      @asserts.push "Skip: #{str} #{iso} #{e.cause}"
      t_print('?')
    else
      @asserts.push(assertion_string("#{e.class}: ", str, iso, e))
      @kill_test += 1
      t_print('X')
    end
  ensure
    @mrbtest_assert = nil
  end

  def assertion_diff(exp, act)
    "    Expected: #{exp.inspect}\n" \
      "      Actual: #{act.inspect}"
  end

  def assert_true(ret, msg = nil, diff = nil)
    if @mrbtest_assert
      @mrbtest_assert_idx += 1
      unless ret
        msg ||= "Expected #{ret.inspect} to be true"
        diff ||= assertion_diff(true, ret)
        @mrbtest_assert.push([@mrbtest_assert_idx, msg, diff])
      end
    end
    ret
  end

  def assert_false(ret, msg = nil, diff = nil)
    if @mrbtest_assert
      @mrbtest_assert_idx += 1
      if ret
        msg ||= "Expected #{ret.inspect} to be false"
        diff ||= assertion_diff(false, ret)
        @mrbtest_assert.push([@mrbtest_assert_idx, msg, diff])
      end
    end
    !ret
  end

  def assert_equal(arg1, arg2 = nil, arg3 = nil)
    exp, act, msg = block_given? ? [arg1, yield, arg2] : [arg1, arg2, arg3]
    msg ||= 'Expected to be equal'
    assert_true(exp == act, msg, assertion_diff(exp, act))
  end

  def assert_not_equal(arg1, arg2 = nil, arg3 = nil)
    exp, act, msg = block_given? ? [arg1, yield, arg2] : [arg1, arg2, arg3]
    msg ||= 'Expected to be not equal'
    assert_false(exp == act, msg, assertion_diff(exp, act))
  end

  def assert_nil(obj, msg = nil)
    msg ||= "Expected #{obj.inspect} to be nil"
    assert_true(obj.nil?, msg, assertion_diff(nil, obj))
  end

  def assert_include(collection, obj, msg = nil)
    msg ||= "Expected #{collection.inspect} to include #{obj.inspect}"
    diff = "    Collection: #{collection.inspect}\n" \
           "        Object: #{obj.inspect}"
    assert_true(collection.include?(obj), msg, diff)
  end

  def assert_not_include(collection, obj, msg = nil)
    msg ||= "Expected #{collection.inspect} to not include #{obj.inspect}"
    diff = "    Collection: #{collection.inspect}\n" \
           "        Object: #{obj.inspect}"
    assert_false(collection.include?(obj), msg, diff)
  end

  def assert_raise(*exp)
    ret = true
    if @mrbtest_assert
      @mrbtest_assert_idx += 1
      msg = exp.last.instance_of?(String) ? exp.pop : nil
      msg = msg.to_s + ' : ' if msg
      should_raise = false
      begin
        yield
        should_raise = true
      rescue Exception => e # rubocop:disable Lint/RescueException
        msg = "#{msg}#{exp.inspect} exception expected, not"
        diff = "      Class: <#{e.class}>\n" \
               "    Message: #{e.message}"
        unless exp.any? { |ex| ex.instance_of?(Module) ? e.is_a?(ex) : ex == e.class }
          @mrbtest_assert.push([@mrbtest_assert_idx, msg, diff])
          ret = false
        end
      end
      exp = exp.first if exp.first
      if should_raise
        msg = "#{msg}#{exp.inspect} expected but nothing was raised."
        @mrbtest_assert.push([@mrbtest_assert_idx, msg, nil])
        ret = false
      end
    end
    ret
  end

  def assert_nothing_raised(*exp)
    ret = true
    if @mrbtest_assert
      @mrbtest_assert_idx += 1
      msg = exp.last.instance_of?(String) ? exp.pop : ''
      begin
        yield
      rescue Exception => e # rubocop:disable Lint/RescueException
        msg = "#{msg} exception raised."
        diff = "      Class: <#{e.class}>\n" \
               "    Message: #{e.message}"
        @mrbtest_assert.push([@mrbtest_assert_idx, msg, diff])
        ret = false
      end
    end
    ret
  end

  def assert_kind_of(cls, obj, msg = nil)
    msg ||= "Expected #{obj.inspect} to be a kind of #{cls}, not #{obj.class}"
    assert_true(obj.is_a?(cls), msg, assertion_diff(cls, obj.class))
  end

  def assert_float(exp, act, msg = nil)
    msg ||= "Float #{exp} expected to be equal to float #{act}"
    assert_true(check_float(exp, act), msg, assertion_diff(exp, act))
  end

  def check_float(a, b)
    a = a.to_f
    b = b.to_f
    a.finite? && b.finite? ? (a - b).abs < 1e-12 : true
  end

  class MRubyTestSkip < NotImplementedError
    attr_accessor :cause

    def initialize(cause)
      super()
      @cause = cause
    end
  end

  def skip(cause = '')
    raise MRubyTestSkip.new(cause)
  end

  # Prints the failed tests and the counts, and raises when a test failed or
  # crashed, so that the test file exits non-zero.
  def report
    t_print("\n")
    @asserts.each { |msg| puts msg }
    total = @ok_test + @ko_test + @kill_test
    t_print("Total: #{total}\n")
    t_print("   OK: #{@ok_test}\n")
    t_print("   KO: #{@ko_test}\n")
    t_print("Crash: #{@kill_test}\n")
    t_print(" Time: #{Time.now - @test_start} seconds\n")
    t_print("\n")
    raise 'SimpleTest: a test failed or crashed' if @ko_test.positive? || @kill_test.positive?
  end
end
