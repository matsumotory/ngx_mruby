/*
// ngx_http_mruby_server.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_server.h"

#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/compile.h>
#include <mruby/string.h>
#include <mruby/class.h>

mrb_value ngx_mrb_get_request_var(mrb_state *mrb, mrb_value self);

static mrb_value ngx_mrb_get_server_var_docroot(mrb_state *mrb, mrb_value self)
{
    mrb_value v = ngx_mrb_get_request_var(mrb, self);
    return mrb_funcall(mrb, v, "document_root", 0, NULL);
}

void ngx_mrb_server_class_init(mrb_state *mrb, struct RClass *class)
{
    struct RClass *class_server;

    class_server = mrb_define_class_under(mrb, class, "Server", mrb->object_class);
    mrb_define_method(mrb, class_server, "document_root", ngx_mrb_get_server_var_docroot, ARGS_NONE());
}
