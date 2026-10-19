# The accessors of Nginx::Var, which become methods of Nginx::Var at their
# first use in a worker, and the methods of Nginx::Connection, Nginx::Server
# and Nginx::Request that read a variable. Config:
# test/conf/conf.d/68-var-accessor.conf (port 18159). Hook script:
# test/html/var_accessor.rb, which prints one inspected Array per call;
# "defined" there is [respond_to?(NAME), instance_methods(false).include?(NAME)].
#
# test.sh runs a single nginx process, so the first request of a name defines
# its accessor and the later requests use it. The variables of the server are
# read by no other test, so their accessors do not exist before these cases.
# The cases run in this order; the last one freezes Nginx::Var.

t = SimpleTest.new "ngx_mruby test: Nginx::Var accessors"

def var_accessor(path, headers = {})
  HttpRequest.new.get base(18159) + path, nil, headers
end

t.assert('Nginx::Var - a declared variable gets an accessor at its first read, with the same value', 'GET /declared on 18159') do
  res = var_accessor('/declared')
  t.assert_equal 200, res.code
  t.assert_equal '[[false, false], "initial", [true, true]]', res["body"]
  2.times do
    res = var_accessor('/declared')
    t.assert_equal 200, res.code
    t.assert_equal '[[true, true], "initial", [true, true]]', res["body"]
  end
end

t.assert('Nginx::Var - a declared variable gets a setter at its first assignment, and nginx reads the value', 'GET /setter on 18159') do
  res = var_accessor('/setter')
  t.assert_equal 200, res.code
  t.assert_equal '[[false, false], "changed", [true, true], "changed"]', res["body"]
  t.assert_equal 'changed', res["x-var-accessor-target"]
  res = var_accessor('/setter')
  t.assert_equal 200, res.code
  t.assert_equal '[[true, true], "changed", [true, true], "changed"]', res["body"]
  t.assert_equal 'changed', res["x-var-accessor-target"]
end

t.assert('Nginx::Var - the defined setter called without its value raises ArgumentError and leaves the variable', 'GET /setter_without_value on 18159') do
  res = var_accessor('/setter_without_value')
  t.assert_equal 200, res.code
  t.assert_equal '["raised: ArgumentError: wrong number of arguments (given 0, expected 1) for Nginx::Var#var_accessor_target=", [true, true]]', res["body"]
  t.assert_equal 'initial', res["x-var-accessor-target"]
end

t.assert('Nginx::Var - a prefix variable gets an accessor at its first read, with the value of each request', 'GET /prefix on 18159') do
  res = var_accessor('/prefix?var_accessor_q=hello')
  t.assert_equal 200, res.code
  t.assert_equal '[[false, false], "hello", [true, true]]', res["body"]
  res = var_accessor('/prefix?var_accessor_q=again')
  t.assert_equal 200, res.code
  t.assert_equal '[[true, true], "again", [true, true]]', res["body"]
end

# A worker defines at most 16 accessors of prefix variables. Other tests of
# the suite read some prefix variables before this case (the arg_ ones are
# counted by the hook script), so the case reads 20 new names and expects the
# first ones to get an accessor until the bound and the rest to get none.
t.assert('Nginx::Var - at most 16 prefix variables get an accessor, and the others keep their values', 'GET /prefix_bound on 18159') do
  query = (1..20).map { |i| "var_accessor_bound_#{i}=b#{i}" }.join('&')
  res = var_accessor('/prefix_bound?' + query)
  t.assert_equal 200, res.code
  lines = res["body"].split("\n")
  t.assert_equal 3, lines.size
  arg_before = lines[0].delete('[]').to_i
  t.assert_equal (1..20).map { |i| "b#{i}" }.inspect, lines[1]
  flags = lines[2].delete('[] ').split(',')
  defined = flags.take_while { |f| f == 'true' }.size
  t.assert_true defined >= 1, "a prefix accessor is defined (#{defined})"
  t.assert_true defined <= 16 - arg_before, "#{defined} accessors after #{arg_before} accessors of arg_ names"
  t.assert_equal ['false'] * (20 - defined), flags.drop(defined)

  res = var_accessor('/prefix_past_bound?var_accessor_past=p')
  t.assert_equal 200, res.code
  t.assert_equal '["p", [false, false]]', res["body"]
end

t.assert('Nginx::Var - a name with an uppercase letter reads the variable and gets no accessor', 'GET /uppercase on 18159') do
  2.times do
    res = var_accessor('/uppercase')
    t.assert_equal 200, res.code
    t.assert_equal '[[false, false], "initial", [false, false]]', res["body"]
  end
end

t.assert('Nginx::Var - a name that is not a variable, and a setter of a prefix variable, get no accessor', 'GET /unknown on 18159') do
  res = var_accessor('/unknown')
  t.assert_equal 200, res.code
  t.assert_equal "[nil, [false, false]]\n[nil, [false, false]]\n[nil, [false, false]]", res["body"]
end

t.assert('Nginx::Var - names that are not variable names in nginx keep their behavior and get no accessor', 'GET /other_names on 18159') do
  res = var_accessor('/other_names')
  t.assert_equal 200, res.code
  t.assert_equal "[nil, [false, false]]\n[\"twice\", [false, false], \"twice\"]", res["body"]
end

t.assert('Nginx::Var - an empty name and a name made only of "=" still raise NoMethodError and get no method', 'GET /rejected on 18159') do
  res = var_accessor('/rejected')
  t.assert_equal 200, res.code
  t.assert_equal "[\"raised: NoMethodError: undefined method '' for Nginx::Var\", false]\n[\"raised: NoMethodError: undefined method '=' for Nginx::Var\", false]", res["body"]
end

t.assert('Nginx::Var - a direct call of method_missing does not hide a method of Kernel', 'GET /kernel_name on 18159') do
  2.times do
    res = var_accessor('/kernel_name')
    t.assert_equal 200, res.code
    t.assert_equal '["var-accessor.test", "NGINX", false]', res["body"]
  end
end

t.assert('Nginx::Connection, Nginx::Server and Nginx::Request read the same values as nginx', 'GET /own_methods on 18159') do
  # user:pass, so that nginx has $remote_user, and a Host header with the
  # port, so that $http_host and $host differ
  res = var_accessor('/own_methods', {"Authorization" => "Basic dXNlcjpwYXNz", "Host" => http_host(18159)})
  t.assert_equal 200, res.code
  t.assert_equal 'user', res["x-remote-user"]
  t.assert_equal '127.0.0.1:18159', res["x-http-host"]
  expected = [
    [res["x-remote-addr"], res["x-remote-port"], res["x-server-addr"], res["x-server-port"]],
    [res["x-document-root"], res["x-realpath-root"], res["x-realpath-root"]],
    [res["x-host"], res["x-http-host"], res["x-request-filename"], res["x-remote-user"]],
  ]
  t.assert_equal expected.map(&:inspect).join("\n"), res["body"]
end

t.assert('Nginx::Connection, Nginx::Server and Nginx::Request do not call the object in @iv_var', 'GET /own_methods/fake_var on 18159') do
  res = var_accessor('/own_methods/fake_var')
  t.assert_equal 200, res.code
  t.assert_equal [res["x-remote-addr"], res["x-document-root"], res["x-host"]].inspect, res["body"]
end

t.assert('Nginx::Request#get_body reads the request body', 'POST /own_methods/get_body on 18159') do
  res = HttpRequest.new.post base(18159) + '/own_methods/get_body', 'var accessor body'
  t.assert_equal 200, res.code
  t.assert_equal '"var accessor body"', res["body"]
end

t.assert('Nginx::Connection, Nginx::Server and Nginx::Request raise RuntimeError in mruby_init_code', 'nginx -t') do
  out = nginx_t(<<'CONF')
http {
    mruby_init_code '
        calls = [
          ["remote_ip", lambda { Nginx::Connection.new.remote_ip }],
          ["document_root", lambda { Nginx::Server.new.document_root }],
          ["hostname", lambda { Nginx::Request.new.hostname }],
        ]
        calls.each do |name, call|
          begin
            call.call
            p "var_accessor init #{name}: returned"
          rescue => e
            p "var_accessor init #{name}: #{e.class}: #{e.message}"
          end
        end
    ';
}
CONF
  t.assert_include out, 'test is successful'
  ['remote_ip', 'document_root', 'hostname'].each do |name|
    t.assert_include out, "var_accessor init #{name}: RuntimeError: this method can only be used while processing a request"
  end
  t.assert_not_include out, ': returned'
end

# Last: this freezes Nginx::Var for the rest of the worker. The accessors
# keep working through method_missing, and no method is defined.
t.assert('Nginx::Var - a frozen Nginx::Var reads the variable and gets no accessor', 'GET /frozen on 18159') do
  res = var_accessor('/frozen')
  t.assert_equal 200, res.code
  t.assert_equal '["after freeze", [false, false]]', res["body"]
end

t.report
