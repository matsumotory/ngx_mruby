/*
// ngx_http_mruby_connection.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_connection.h"

#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/compile.h>
#include <mruby/string.h>
#include <mruby/class.h>

mrb_value ngx_mrb_get_request_var(mrb_state *mrb, mrb_value self);

static mrb_value ngx_mrb_get_conn_var_remote_addr(mrb_state *mrb, mrb_value self)
{
    mrb_value v = ngx_mrb_get_request_var(mrb, self);
    return mrb_funcall(mrb, v, "remote_addr", 0, NULL);
}

static mrb_value ngx_mrb_get_conn_var_remote_port(mrb_state *mrb, mrb_value self)
{
    mrb_value v = ngx_mrb_get_request_var(mrb, self);
    return mrb_funcall(mrb, v, "remote_port", 0, NULL);
}

void ngx_mrb_conn_class_init(mrb_state *mrb, struct RClass *class)
{
    struct RClass *class_conn;

    class_conn = mrb_define_class_under(mrb, class, "Connection", mrb->object_class);
    mrb_define_method(mrb, class_conn, "remote_ip", ngx_mrb_get_conn_var_remote_addr, ARGS_NONE());
    mrb_define_method(mrb, class_conn, "remote_port", ngx_mrb_get_conn_var_remote_port, ARGS_NONE());
}
