# ngx_mruby over HTTP/2 and HTTP/3: each request goes to the same server
# with HTTP/1.1, HTTP/2 and HTTP/3 (HttpVersions in test/t/client.rb), and
# each version must get the same response from ngx_mruby's handlers,
# filters and SSL handshake handler.
# Config: test/conf/conf.d/78-http2-http3.conf (port 18173, TCP and QUIC).
#
# Each assertion first checks that the response came with the version that
# the request asked for, so that a fallback to another version fails the
# case instead of hiding the version.

t = SimpleTest.new "ngx_mruby test: HTTP/1.1, HTTP/2 and HTTP/3"

HTTP2_HTTP3_PORT = 18173

# The response of each version to the same request, as a Hash from the
# version to the response.
def http2_http3_responses(path, **options)
  HttpVersions::VERSIONS.to_h do |version|
    [version, HttpVersions.request(version, HTTP2_HTTP3_PORT, path, **options)]
  end
end

# Asserts the version of each response, then yields each response with its
# version for the assertions of the request.
def http2_http3_each(t, responses)
  responses.each do |version, res|
    t.assert_equal version, res.version, "HTTP/#{version} answered with HTTP/#{res.version}"
    yield version, res
  end
end

PROTOCOLS = { '1.1' => 'HTTP/1.1', '2' => 'HTTP/2.0', '3' => 'HTTP/3.0' }.freeze

t.assert('http2_http3 - nginx takes each request with the version that the client asked for', 'GET /protocol') do
  http2_http3_each(t, http2_http3_responses('/protocol')) do |version, res|
    t.assert_equal 200, res.code, "status over HTTP/#{version}"
    t.assert_equal PROTOCOLS[version], res.body, "$server_protocol over HTTP/#{version}"
  end
end

t.assert('http2_http3 - a content handler sets the status, the Content-Type, a header and the body', 'GET /content') do
  http2_http3_each(t, http2_http3_responses('/content')) do |version, res|
    t.assert_equal 201, res.code, "status over HTTP/#{version}"
    t.assert_equal 'text/x-http2-http3', res.headers['content-type'], "Content-Type over HTTP/#{version}"
    t.assert_equal 'content', res.headers['x-out'], "X-Out over HTTP/#{version}"
    t.assert_equal 'content body', res.body, "body over HTTP/#{version}"
  end
end

t.assert('http2_http3 - Nginx::Headers_in reads, adds and deletes the headers of the request', 'GET /headers_in') do
  responses = http2_http3_responses('/headers_in', headers: { 'X-Test' => 'from client', 'X-Deleted' => 'here' })
  http2_http3_each(t, responses) do |version, res|
    t.assert_equal 200, res.code, "status over HTTP/#{version}"
    t.assert_equal 'x-test="from client" host="localhost:18173" x-added="added" x-deleted=nil', res.body,
                   "body over HTTP/#{version}"
  end
end

t.assert('http2_http3 - Nginx::Headers_out sets, replaces and deletes the headers of the response', 'GET /headers_out') do
  http2_http3_each(t, http2_http3_responses('/headers_out')) do |version, res|
    t.assert_equal 200, res.code, "status over HTTP/#{version}"
    t.assert_equal 'set', res.headers['x-set'], "X-Set over HTTP/#{version}"
    t.assert_equal 'second', res.headers['x-replaced'], "X-Replaced over HTTP/#{version}"
    t.assert_nil res.headers['x-deleted'], "X-Deleted over HTTP/#{version}"
    t.assert_equal 'application/x-http2-http3', res.headers['content-type'], "Content-Type over HTTP/#{version}"
    t.assert_equal 'https://localhost:18173/headers_out_location', res.headers['location'],
                   "Location over HTTP/#{version}"
    t.assert_equal 'x-set="set" x-deleted=nil', res.body, "body over HTTP/#{version}"
  end
end

t.assert('http2_http3 - a content handler reads a short request body', 'POST /body') do
  http2_http3_each(t, http2_http3_responses('/body', method: 'POST', body: 'short body')) do |version, res|
    t.assert_equal 200, res.code, "status over HTTP/#{version}"
    t.assert_equal '10:short body', res.body, "body over HTTP/#{version}"
  end
end

# 100,000 bytes, more than client_body_buffer_size (16k on 64-bit
# platforms), so nginx keeps the body in a temporary file; the response is
# as long, so that the output also goes out in several frames.
LARGE_BODY = (0...100_000).map { |i| (97 + i % 26).chr }.join.b

t.assert('http2_http3 - a content handler reads a request body of 100,000 bytes and writes it back', 'POST /body') do
  http2_http3_each(t, http2_http3_responses('/body', method: 'POST', body: LARGE_BODY)) do |version, res|
    t.assert_equal 200, res.code, "status over HTTP/#{version}"
    t.assert_equal 100_007, res.body.bytesize, "length of the body over HTTP/#{version}"
    t.assert_true res.body == "100000:#{LARGE_BODY}", "the body over HTTP/#{version} is the request body after \"100000:\""
  end
end

t.assert('http2_http3 - a header filter and a body filter change the output of a content handler', 'GET /filter') do
  http2_http3_each(t, http2_http3_responses('/filter')) do |version, res|
    t.assert_equal 200, res.code, "status over HTTP/#{version}"
    t.assert_equal 'ran', res.headers['x-header-filter'], "X-Header-Filter over HTTP/#{version}"
    t.assert_equal 'ORIGIN (body filter)', res.body, "body over HTTP/#{version}"
  end
end

t.assert('http2_http3 - Nginx::Async.sleep in a content handler', 'GET /sleep') do
  http2_http3_each(t, http2_http3_responses('/sleep')) do |version, res|
    t.assert_equal 200, res.code, "status over HTTP/#{version}"
    t.assert_equal 'slept', res.body, "body over HTTP/#{version}"
  end
end

t.assert('http2_http3 - Nginx::Async::HTTP.sub_request from a content handler', 'GET /sub_request') do
  http2_http3_each(t, http2_http3_responses('/sub_request')) do |version, res|
    t.assert_equal 200, res.code, "status over HTTP/#{version}"
    t.assert_equal 'sub_request=200 leaf', res.body, "body over HTTP/#{version}"
  end
end

# Each request has a connection of its own, so each runs the SSL handshake
# handler once: the second request of a version sees one handshake more
# than the first. The handler saw the server name of the client and TLS
# 1.3, which QUIC requires and which nginx offers by default to the others.
t.assert('http2_http3 - the SSL handshake handler runs for the handshake of each connection', 'GET /handshake') do
  HttpVersions::VERSIONS.each do |version|
    first, second = Array.new(2) { HttpVersions.request(version, HTTP2_HTTP3_PORT, '/handshake') }
    [first, second].each do |res|
      t.assert_equal version, res.version, "HTTP/#{version} answered with HTTP/#{res.version}"
      t.assert_equal 200, res.code, "status over HTTP/#{version}"
    end
    count1, seen1 = first.body.split(' ', 2)
    count2, seen2 = second.body.split(' ', 2)
    t.assert_equal count1.to_i + 1, count2.to_i, "handshakes between two requests over HTTP/#{version}"
    t.assert_equal 'localhost TLSv1.3', seen1, "what the handler saw over HTTP/#{version}"
    t.assert_equal 'localhost TLSv1.3', seen2, "what the handler saw over HTTP/#{version}"
  end
end

t.report
