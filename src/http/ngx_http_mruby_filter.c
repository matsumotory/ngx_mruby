/*
// ngx_http_mruby_filter.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_filter.h"
#include "ngx_http_mruby_module.h"
#include "ngx_http_mruby_request.h"
#include "ngx_http_mruby_core.h"

#include <mruby.h>
#include <mruby/class.h>
#include <mruby/compile.h>
#include <mruby/data.h>
#include <mruby/proc.h>
#include <mruby/string.h>

static mrb_value ngx_mrb_get_filter_body(mrb_state *mrb, mrb_value self)
{
  ngx_http_request_t *r = ngx_mrb_get_request();
  ngx_http_mruby_ctx_t *ctx = ngx_mrb_http_get_module_ctx(mrb, r);

  return mrb_str_new(mrb, (char *)ctx->body, ctx->body_length);
}

static mrb_value ngx_mrb_set_filter_body(mrb_state *mrb, mrb_value self)
{
  ngx_http_request_t *r = ngx_mrb_get_request();
  ngx_http_mruby_ctx_t *ctx = ngx_mrb_http_get_module_ctx(mrb, r);
  mrb_value body;

  mrb_get_args(mrb, "o", &body);
  if (mrb_type(body) != MRB_TT_STRING) {
    body = mrb_funcall(mrb, body, "to_s", 0, NULL);
  }

  ctx->body_length = RSTRING_LEN(body);
  ctx->body = ngx_palloc(r->pool, ctx->body_length);
  ngx_memcpy(ctx->body, RSTRING_PTR(body), ctx->body_length);

  return mrb_fixnum_value(ctx->body_length);
}

void ngx_mrb_filter_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_filter;

  class_filter = mrb_define_class_under(mrb, class, "Filter", mrb->object_class);
  mrb_define_method(mrb, class_filter, "body", ngx_mrb_get_filter_body, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_filter, "body=", ngx_mrb_set_filter_body, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_filter, "output", ngx_mrb_set_filter_body, MRB_ARGS_REQ(1));
}
