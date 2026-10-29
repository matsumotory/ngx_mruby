# Nginx::Var with input from the configuration code that it has to reject or
# must not change. Config: test/conf/conf.d/67-var-input.conf (port 18153).
# Hook script: test/html/var_input.rb.
#
# Each request starts with $var_input_target set to "initial". The hook
# script answers 200 with "returned: VALUE" when its call returns and with
# "raised: CLASS: MESSAGE" when the call raises, and adds $var_input_target
# after the call on a second line.
#
# The cases of a bad name and of a setter without its value come last:
# before the fix, these calls could end the nginx process (test.sh runs a
# single process), and the cases after them would get no answer.

t = SimpleTest.new "ngx_mruby test: Nginx::Var input"

def var_input(path)
  HttpRequest.new.get base(18153) + path
end

def var_input_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

# Lines that nginx appended to error.log after offset.
def var_input_log_lines(offset)
  File.open(var_input_log_path) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
end

t.assert('Nginx::Var - the accessor reads the variable, also with an uppercase name', 'GET /get and /get_uppercase on 18153') do
  res = var_input('/get')
  t.assert_equal 200, res.code
  t.assert_equal "returned: \"initial\"\nvar_input_target: \"initial\"", res["body"]
  res = var_input('/get_uppercase')
  t.assert_equal 200, res.code
  t.assert_equal "returned: \"initial\"\nvar_input_target: \"initial\"", res["body"]
end

t.assert('Nginx::Var - the setter and set write the variable and return the value', 'GET /setter and /set on 18153') do
  res = var_input('/setter')
  t.assert_equal 200, res.code
  t.assert_equal "returned: \"changed\"\nvar_input_target: \"changed\"", res["body"]
  res = var_input('/set')
  t.assert_equal 200, res.code
  t.assert_equal "returned: \"set\"\nvar_input_target: \"set\"", res["body"]
end

# set looks the variable up by the lowercased name, and leaves the String
# that the caller passed as it was.
t.assert('Nginx::Var - set with a frozen String sets the variable and leaves the String unchanged', 'GET /set_frozen_key on 18153') do
  res = var_input('/set_frozen_key')
  t.assert_equal 200, res.code
  t.assert_equal "returned: [true, \"Var_Input_Target\"]\nvar_input_target: \"frozen key\"", res["body"]
end

t.assert('Nginx::Var - set with a Symbol sets the variable and leaves the name of the Symbol unchanged', 'GET /set_symbol_key on 18153') do
  res = var_input('/set_symbol_key')
  t.assert_equal 200, res.code
  t.assert_equal "returned: [\"Var_Input_Target_Set_By_A_Symbol\", \"symbol key\"]\nvar_input_target: \"initial\"", res["body"]
end

t.assert('Nginx::Var - set leaves a String that shares its bytes with the name unchanged', 'GET /set_shared_key on 18153') do
  name = 'Var_Input_Target_' + 'Shared' * 6
  res = var_input('/set_shared_key')
  t.assert_equal 200, res.code
  t.assert_equal "returned: [#{name.inspect}, #{name.inspect}]\nvar_input_target: \"initial\"", res["body"]
end

t.assert('Nginx::Var - the error line of a variable without a value names the variable exactly', 'GET /realpath_root on 18153') do
  offset = File.size(var_input_log_path)
  res = var_input('/realpath_root')
  t.assert_equal 200, res.code
  t.assert_equal "returned: nil\nvar_input_target: \"initial\"", res["body"]
  lines = var_input_log_lines(offset).select { |l| l.include?('ngx_mrb_var_get:') }
  t.assert_equal 1, lines.size
  t.assert_include lines[0].to_s, ': realpath_root is NULL, client: '
end

# mruby_init_code runs while nginx reads the configuration, outside any
# request. nginx -t runs it (see nginx_t in test/t/cases/_prelude.rb), and
# the code prints what each call did.
t.assert('Nginx::Var - the methods raise RuntimeError in mruby_init_code', 'nginx -t') do
  out = nginx_t(<<'CONF')
http {
    mruby_init_code '
        v = Nginx::Var.new
        calls = [
          ["getter", lambda { v.var_input_target }],
          ["setter", lambda { v.var_input_target = "x" }],
          ["empty name", lambda { v.send("") }],
          ["set", lambda { v.set("var_input_target", "x") }],
          ["exist?", lambda { v.exist?("var_input_target") }],
        ]
        calls.each do |name, call|
          begin
            call.call
            p "var_input init #{name}: returned"
          rescue => e
            p "var_input init #{name}: #{e.class}: #{e.message}"
          end
        end
    ';
}
CONF
  t.assert_include out, 'test is successful'
  ['getter', 'setter', 'empty name', 'set', 'exist?'].each do |name|
    t.assert_include out, "var_input init #{name}: RuntimeError: this method can only be used while processing a request"
  end
  t.assert_not_include out, ': returned'
end

t.assert('Nginx::Var - an empty name raises NoMethodError', 'GET /empty_name on 18153') do
  res = var_input('/empty_name')
  t.assert_equal 200, res.code
  t.assert_equal "raised: NoMethodError: undefined method '' for Nginx::Var\nvar_input_target: \"initial\"", res["body"]
end

t.assert('Nginx::Var - a name made only of "=" raises NoMethodError', 'GET /equal_sign_only on 18153') do
  res = var_input('/equal_sign_only')
  t.assert_equal 200, res.code
  t.assert_equal "raised: NoMethodError: undefined method '=' for Nginx::Var\nvar_input_target: \"initial\"", res["body"]
end

t.assert('Nginx::Var - a setter without its value raises ArgumentError and leaves the variable', 'GET /setter_without_value on 18153') do
  res = var_input('/setter_without_value')
  t.assert_equal 200, res.code
  t.assert_equal "raised: ArgumentError: wrong number of arguments (given 0, expected 1) for Nginx::Var#var_input_target=\nvar_input_target: \"initial\"", res["body"]
end

t.assert('Nginx::Var - the accessor keeps a value that contains a NUL byte', 'GET /set_nul_value on 18153') do
  res = var_input('/set_nul_value')
  t.assert_equal 200, res.code
  t.assert_equal "returned: [true, 5]\nvar_input_target: \"restored\"", res["body"]
end

t.assert('Nginx::Var - set keeps a value that contains a NUL byte', 'GET /set_nul_value_via_set on 18153') do
  res = var_input('/set_nul_value_via_set')
  t.assert_equal 200, res.code
  t.assert_equal "returned: [true, 5]\nvar_input_target: \"restored\"", res["body"]
end

t.report
