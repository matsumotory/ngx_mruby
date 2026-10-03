/*
// ngx_http_mruby_filter.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_filter.h"

#include "ngx_http_mruby_core.h"
#include "ngx_http_mruby_request.h"

#include <mruby/string.h>

static mrb_value ngx_mrb_get_filter_body(mrb_state *mrb, mrb_value self)
{
  ngx_http_request_t *r = ngx_mrb_get_request_or_raise(mrb);
  ngx_http_mruby_ctx_t *ctx = ngx_mrb_http_get_module_ctx(mrb, r);

  /*
   * The body is buffered only by the body filter. Before that (for example in
   * a header filter) ctx->body is NULL while ctx->body_length already holds the
   * Content-Length, and mrb_str_new() would return that many uninitialized bytes.
   */
  if (ctx->body == NULL) {
    return mrb_str_new(mrb, NULL, 0);
  }

  return mrb_str_new(mrb, (char *)ctx->body, ctx->body_length);
}

static mrb_value ngx_mrb_set_filter_body(mrb_state *mrb, mrb_value self)
{
  ngx_http_request_t *r = ngx_mrb_get_request_or_raise(mrb);
  ngx_http_mruby_ctx_t *ctx = ngx_mrb_http_get_module_ctx(mrb, r);
  mrb_value body;

  /*
   * The body filter reads the response into ctx->body and sends ctx->body
   * afterwards. A body set anywhere else would be taken for the buffer that
   * the body filter reads into.
   */
  if (ctx->phase != NGX_HTTP_MRUBY_FILTER_PROCESS) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "Nginx::Filter#body= can only be used in an output body filter");
  }

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
