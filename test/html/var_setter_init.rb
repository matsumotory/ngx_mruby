# Hook script of test/conf/conf.d/72-var-setter-init.conf (port 18104), for
# test/t/cases/var_setter_init.rb. $args has a set_handler. The script assigns
# it through the setter of Nginx::Var (/setter) or Nginx::Var#set (/set), reads
# it back, and answers "args: VALUE".
v = Nginx::Var.new
case Nginx::Request.new.uri
when '/setter'
  v.args = 'setter=1'
  Nginx.rputs "args: #{v.args}"
when '/set'
  v.set('args', 'set=1')
  Nginx.rputs "args: #{v.args}"
else
  Nginx.return Nginx::HTTP_NOT_FOUND
end
