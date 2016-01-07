/*
// ngx_http_mruby_ssl.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_ssl.h"

#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/compile.h>
#include <mruby/string.h>
#include <mruby/class.h>

static mrb_value ngx_mrb_ssl_set_cert(mrb_state *mrb, mrb_value self)
{
  return self;
}

static mrb_value ngx_mrb_ssl_set_cert_key(mrb_state *mrb, mrb_value self)
{
  return self;
}

void ngx_mrb_ssl_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_ssl;

  class_ssl = mrb_define_class_under(mrb, class, "SSL", mrb->object_class);
  mrb_define_method(mrb, class_ssl, "certificate=", ngx_mrb_ssl_set_cert, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_ssl, "certificate_key=", ngx_mrb_ssl_set_cert_key, MRB_ARGS_REQ(1));
}
