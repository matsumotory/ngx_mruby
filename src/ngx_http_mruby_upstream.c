/*
// ngx_http_mruby_upstream.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_upstream.h"

#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/compile.h>
#include <mruby/string.h>
#include <mruby/class.h>

static mrb_value ngx_mrb_upstream_init(mrb_state *mrb, mrb_value self)
{
  return mrb_nil_value();
}

static mrb_value ngx_mrb_upstream_set_keepalive(mrb_state *mrb, mrb_value self)
{
  return mrb_nil_value();
}

static mrb_value ngx_mrb_upstream_set_cache(mrb_state *mrb, mrb_value self)
{
  return mrb_nil_value();
}

static mrb_value ngx_mrb_upstream_get_hostname(mrb_state *mrb, mrb_value self)
{
  return mrb_nil_value();
}

void ngx_mrb_upstream_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_upstream;

  class_upstream = mrb_define_class_under(mrb, class, "Upstream", mrb->object_class);
  mrb_define_method(mrb, class_upstream, "initialize", ngx_mrb_upstream_init, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_upstream, "keepalive=", ngx_mrb_upstream_set_keepalive, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_upstream, "keepalive_cache=", ngx_mrb_upstream_set_cache, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_upstream, "hostname", ngx_mrb_upstream_get_hostname, MRB_ARGS_NONE());
}
