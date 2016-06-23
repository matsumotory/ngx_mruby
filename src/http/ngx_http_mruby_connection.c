/*
// ngx_http_mruby_connection.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_connection.h"

#include <mruby.h>
#include <mruby/class.h>
#include <mruby/compile.h>
#include <mruby/data.h>
#include <mruby/proc.h>
#include <mruby/string.h>

// extern from ngx_http_mruby_request.c
extern mrb_value ngx_mrb_get_request_var(mrb_state *mrb, mrb_value self);

static mrb_value ngx_mrb_get_conn_var_remote_addr(mrb_state *mrb, mrb_value self)
{
  return mrb_funcall(mrb, ngx_mrb_get_request_var(mrb, self), "remote_addr", 0, NULL);
}

static mrb_value ngx_mrb_get_conn_var_remote_port(mrb_state *mrb, mrb_value self)
{
  return mrb_funcall(mrb, ngx_mrb_get_request_var(mrb, self), "remote_port", 0, NULL);
}

static mrb_value ngx_mrb_get_conn_var_server_addr(mrb_state *mrb, mrb_value self)
{
  return mrb_funcall(mrb, ngx_mrb_get_request_var(mrb, self), "server_addr", 0, NULL);
}

static mrb_value ngx_mrb_get_conn_var_server_port(mrb_state *mrb, mrb_value self)
{
  return mrb_funcall(mrb, ngx_mrb_get_request_var(mrb, self), "server_port", 0, NULL);
}

void ngx_mrb_conn_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_conn;

  class_conn = mrb_define_class_under(mrb, class, "Connection", mrb->object_class);
  mrb_define_method(mrb, class_conn, "remote_ip", ngx_mrb_get_conn_var_remote_addr, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_conn, "remote_port", ngx_mrb_get_conn_var_remote_port, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_conn, "local_ip", ngx_mrb_get_conn_var_server_addr, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_conn, "local_port", ngx_mrb_get_conn_var_server_port, MRB_ARGS_NONE());
}
