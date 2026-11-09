# Hook script of the mruby_set directive of
# test/conf/conf.d/83-var-value-to-s.conf (port 18189), for
# test/t/cases/var_value_to_s.rb. The path is /set/<wait>/<value>.
#
# <wait> is nowait, or sleep, which calls Nginx::Async.sleep before the rest.
# <value> is what the code does:
#
#   string             returns "set"
#   integer            returns 1, whose to_s returns "1"
#   no_to_s            returns a BasicObject, which has no to_s
#   to_s_raises        returns an object whose to_s raises
#   to_s_not_string    returns an object whose to_s returns an Integer
#   setter_not_string  sets $var_value_to_s with the setter of Nginx::Var to
#                      that object, and returns "set"
#   set_not_string     the same with Nginx::Var#set
parts = Nginx::Request.new.uri.split('/')
Nginx::Async.sleep 10 if parts[2] == 'sleep'

def var_value_to_s_not_string
  o = Object.new
  def o.to_s
    1
  end
  o
end

case parts[3]
when 'string'
  'set'
when 'integer'
  1
when 'no_to_s'
  BasicObject.new
when 'to_s_raises'
  o = Object.new
  def o.to_s
    raise 'raised in to_s'
  end
  o
when 'to_s_not_string'
  var_value_to_s_not_string
when 'setter_not_string'
  Nginx::Var.new.var_value_to_s = var_value_to_s_not_string
  'set'
when 'set_not_string'
  Nginx::Var.new.set 'var_value_to_s', var_value_to_s_not_string
  'set'
else
  raise "no value for #{parts[3]}"
end
