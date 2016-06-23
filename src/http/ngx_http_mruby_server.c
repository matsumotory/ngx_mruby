/*
// ngx_http_mruby_server.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_server.h"

#include <mruby.h>
#include <mruby/class.h>
#include <mruby/compile.h>
#include <mruby/data.h>
#include <mruby/proc.h>
#include <mruby/string.h>

// extern from ngx_http_mruby_request.c
extern mrb_value ngx_mrb_get_request_var(mrb_state *mrb, mrb_value self);

static mrb_value ngx_mrb_get_server_var_docroot(mrb_state *mrb, mrb_value self)
{
  return mrb_funcall(mrb, ngx_mrb_get_request_var(mrb, self), "document_root", 0, NULL);
}

static mrb_value ngx_mrb_get_server_var_realpath_root(mrb_state *mrb, mrb_value self)
{
  return mrb_funcall(mrb, ngx_mrb_get_request_var(mrb, self), "realpath_root", 0, NULL);
}

void ngx_mrb_server_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_server;

  class_server = mrb_define_class_under(mrb, class, "Server", mrb->object_class);
  mrb_define_method(mrb, class_server, "document_root", ngx_mrb_get_server_var_docroot, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_server, "path", ngx_mrb_get_server_var_realpath_root, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_server, "realpath_root", ngx_mrb_get_server_var_realpath_root, MRB_ARGS_NONE());
}
