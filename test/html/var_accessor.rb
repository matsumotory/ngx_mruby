# Hook script of test/conf/conf.d/68-var-accessor.conf (port 18159), for
# test/t/cases/var_accessor.rb. It makes the calls that the path of the
# request names and answers 200 with one line per call, each the inspect of
# an Array. "defined" stands for [v.respond_to?(NAME),
# Nginx::Var.instance_methods(false).include?(NAME)]: whether Nginx::Var has
# a method of that name. A call that raises is shown as
# "raised: CLASS: MESSAGE".
#
# The script defines no method of its own: a def at the top level would add
# a method to Object for the rest of the worker.
v = Nginx::Var.new
path = Nginx::Request.new.uri

defined = lambda do |name|
  [v.respond_to?(name), Nginx::Var.instance_methods(false).include?(name)]
end

attempt = lambda do |pr|
  begin
    pr.call
  rescue => e
    "raised: #{e.class}: #{e.message}"
  end
end

lines =
  case path
  when '/declared'
    before = defined.call(:var_accessor_declared)
    value = v.var_accessor_declared
    [[before, value, defined.call(:var_accessor_declared)]]
  when '/setter'
    before = defined.call(:var_accessor_target=)
    value = v.send(:var_accessor_target=, 'changed')
    [[before, value, defined.call(:var_accessor_target=), v.var_accessor_target]]
  when '/setter_without_value'
    [[attempt.call(lambda { v.send(:var_accessor_target=) }), defined.call(:var_accessor_target=)]]
  when '/prefix'
    before = defined.call(:arg_var_accessor_q)
    value = v.arg_var_accessor_q
    [[before, value, defined.call(:arg_var_accessor_q)]]
  when '/prefix_bound'
    # The accessors of prefix names that the worker has from other tests;
    # nginx declares no variable whose name starts with arg_.
    arg_before = Nginx::Var.instance_methods(false).count { |m| m.to_s.start_with?('arg_') }
    names = (1..20).map { |i| "arg_var_accessor_bound_#{i}".to_sym }
    values = names.map { |n| v.send(n) }
    [[arg_before], values, names.map { |n| v.respond_to?(n) }]
  when '/prefix_past_bound'
    value = v.arg_var_accessor_past
    [[value, defined.call(:arg_var_accessor_past)]]
  when '/uppercase'
    before = defined.call(:Var_Accessor_Declared)
    value = v.Var_Accessor_Declared
    [[before, value, defined.call(:Var_Accessor_Declared)]]
  when '/unknown'
    get = v.var_accessor_no_such_variable
    set = v.send(:var_accessor_no_such_variable=, 'x')
    prefix_set = v.send(:arg_var_accessor_set=, 'x')
    [
      [get, defined.call(:var_accessor_no_such_variable)],
      [set, defined.call(:var_accessor_no_such_variable=)],
      [prefix_set, defined.call(:arg_var_accessor_set=)],
    ]
  when '/other_names'
    # A name with a character that no nginx variable name has, and a setter
    # name with more than one "=" (the variable is the part before the first
    # "=").
    space = v.send(:'arg_var accessor')
    twice = v.send(:'var_accessor_declared==', 'twice')
    [
      [space, defined.call(:'arg_var accessor')],
      [twice, defined.call(:'var_accessor_declared=='), v.var_accessor_declared],
    ]
  when '/rejected'
    [
      [attempt.call(lambda { v.send('') }), Nginx::Var.instance_methods(false).include?(:'')],
      [attempt.call(lambda { v.send('=', 'x') }), Nginx::Var.instance_methods(false).include?(:'=')],
    ]
  when '/kernel_name'
    # Kernel#server_name answers v.server_name; a direct call of
    # method_missing reads $server_name and must not hide Kernel#server_name.
    direct = v.method_missing(:server_name)
    [[direct, v.server_name, Nginx::Var.instance_methods(false).include?(:server_name)]]
  when '/own_methods'
    c = Nginx::Connection.new
    s = Nginx::Server.new
    r = Nginx::Request.new
    [
      [c.remote_ip, c.remote_port, c.local_ip, c.local_port],
      [s.document_root, s.realpath_root, s.path],
      [r.hostname, r.authority, r.filename, r.user],
    ]
  when '/own_methods/fake_var'
    # The objects keep the Nginx::Var that they use in @iv_var. With an
    # object of another class there, the methods show whether they call it.
    fake = Object.new
    def fake.remote_addr
      'fake remote_addr'
    end

    def fake.document_root
      'fake document_root'
    end

    def fake.host
      'fake host'
    end
    c = Nginx::Connection.new
    s = Nginx::Server.new
    r = Nginx::Request.new
    [c, s, r].each { |o| o.instance_variable_set(:@iv_var, fake) }
    [[c.remote_ip, s.document_root, r.hostname]]
  when '/frozen'
    # Last of the cases: Nginx::Var stays frozen for the rest of the worker.
    Nginx::Var.freeze
    value = attempt.call(lambda { v.var_accessor_after_freeze })
    [[value, defined.call(:var_accessor_after_freeze)]]
  else
    raise "no call for #{path}"
  end

Nginx.rputs lines.map(&:inspect).join("\n")
