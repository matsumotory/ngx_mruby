# Nginx::Var assigns $args, a variable that has a set_handler, and reads it
# back. Config: test/conf/conf.d/72-var-setter-init.conf (port 18104). Hook
# script: test/html/var_setter_init.rb.
#
# $args is NGX_HTTP_VAR_CHANGEABLE and has a set_handler
# (ngx_http_variable_set_args). The setter of Nginx::Var and Nginx::Var#set
# reach the set_handler. Before the fix, they passed a value struct straight
# from ngx_palloc, whose len, data and flags the set_handler read
# uninitialised, so the assigned query string did not reach r->args: the
# read-back returned a wrong value, or the uninitialised pointer ended the
# nginx process (test.sh runs a single process). The fix fills the struct
# before the call, as nginx does, so the value round-trips.

t = SimpleTest.new "ngx_mruby test: Nginx::Var sets a variable with a set_handler"

def var_setter_init(path)
  HttpRequest.new.get base(18104) + path
end

t.assert('Nginx::Var - the setter sets $args, with the set_handler, and it reads back', 'GET /setter on 18104') do
  res = var_setter_init('/setter')
  t.assert_equal 200, res.code
  t.assert_equal 'args: setter=1', res['body']
end

t.assert('Nginx::Var - set sets $args, with the set_handler, and it reads back', 'GET /set on 18104') do
  res = var_setter_init('/set')
  t.assert_equal 200, res.code
  t.assert_equal 'args: set=1', res['body']
end

t.report
