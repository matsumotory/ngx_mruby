# A Request setter (Nginx::Request#content_type= stands for the seven setters,
# which share one macro), Nginx::Async::HTTP.sub_request and
# Nginx::Headers_out#[]= raise TypeError for an argument that is not a String,
# as Nginx.rputs and the Nginx::Var setter already do. Nginx::Headers_in#[]
# returns an Array when a header name is sent more than once, so this test
# passes that Array, and a plain String, to each method and checks the result.
# Config: test/conf/conf.d/95-type-unchecked-reads.conf (port 18172).
#
# The case that confirms the worker still answers comes last.

t = SimpleTest.new "ngx_mruby test: a setter, sub_request and Headers#[]= check that the argument is a String"

TYPE_UNCHECKED_PORT = 18172

# Sends GET path over HTTP/1.0 with the header X-Dup given `dup` times and
# returns the connection status and the body. With one X-Dup the handler reads
# a String from headers_in[]; with two it reads an Array.
def type_unchecked_get(path, dup)
  req = "GET #{path} HTTP/1.0\r\nHost: localhost\r\n"
  dup.times { |i| req += "X-Dup: v#{i}\r\n" }
  req += "\r\n"
  status, raw = tcp_client(TYPE_UNCHECKED_PORT, req)
  _, body = raw.to_s.split("\r\n\r\n", 2)
  [status, body.to_s]
end

# With the header sent once the value is a String and the method accepts it.
{
  '/setter' => 'ok',
  '/headers_set' => 'ok',
}.each do |path, expected|
  t.assert('type unchecked reads', "#{path} with a String header value is accepted") do
    status, body = type_unchecked_get(path, 1)
    t.assert_equal 'EOF', status
    t.assert_equal expected, body
  end
end

# With the header sent twice the value is an Array, and the method raises
# TypeError.
['/setter', '/headers_set', '/sub_request_path'].each do |path|
  t.assert('type unchecked reads', "#{path} with an Array header value raises TypeError") do
    status, body = type_unchecked_get(path, 2)
    t.assert_equal 'EOF', status
    t.assert_true body.start_with?('raised: TypeError: '), "expected a TypeError, got: #{body.inspect}"
    t.assert_include body, 'cannot be converted to String'
  end
end

# The worker still answers after the Array values above.
t.assert('type unchecked reads', 'the server answers after the Array header values') do
  status, body = type_unchecked_get('/alive', 1)
  t.assert_equal 'EOF', status
  t.assert_equal 'alive', body
end

t.report
