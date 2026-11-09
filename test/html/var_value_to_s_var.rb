# Hook script of the content handler of /var/ in
# test/conf/conf.d/83-var-value-to-s.conf (port 18189), for
# test/t/cases/var_value_to_s.rb. The path is /var/<call>/<value>.
#
# <call> is setter (Nginx::Var#var_value_to_s=), set
# (Nginx::Var#set "var_value_to_s", value) or set_name (Nginx::Var#set with
# the value as the name and "x" as the value). <value> is string ("changed"),
# no_to_s (a BasicObject, which has no to_s), to_s_raises (an object whose
# to_s raises) or to_s_not_string (an object whose to_s returns an Integer).
#
# The script answers 200 with "returned: VALUE" when the call returns and
# with "raised: CLASS: MESSAGE" when it raises, and adds $var_value_to_s after
# the call on a second line. The server sets it to "initial" for each
# request.
v = Nginx::Var.new
parts = Nginx::Request.new.uri.split('/')

value =
  case parts[3]
  when 'string'
    'changed'
  when 'no_to_s'
    BasicObject.new
  when 'to_s_raises'
    o = Object.new
    def o.to_s
      raise 'raised in to_s'
    end
    o
  when 'to_s_not_string'
    o = Object.new
    def o.to_s
      1
    end
    o
  else
    raise "no value for #{parts[3]}"
  end

begin
  result =
    case parts[2]
    when 'setter'
      v.var_value_to_s = value
    when 'set'
      v.set 'var_value_to_s', value
    when 'set_name'
      v.set value, 'x'
    else
      raise "no call for #{parts[2]}"
    end
  Nginx.rputs "returned: #{result.inspect}\n"
rescue => e
  Nginx.rputs "raised: #{e.class}: #{e.message}\n"
end
Nginx.rputs "var_value_to_s: #{v.var_value_to_s.inspect}"
