/*
// ngx_http_mruby_filter.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_module.h"
#include "ngx_http_mruby_filter.h"
#include "ngx_http_mruby_request.h"

#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/compile.h>
#include <mruby/string.h>
#include <mruby/class.h>

static mrb_value ngx_mrb_get_filter_body(mrb_state *mrb, mrb_value self)
{
  ngx_http_request_t *r = ngx_mrb_get_request();
  ngx_http_mruby_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);

  return mrb_str_new(mrb, (char *)ctx->body, ctx->body_length);
}

static mrb_value ngx_mrb_set_filter_body(mrb_state *mrb, mrb_value self)
{
  ngx_http_request_t *r = ngx_mrb_get_request();
  ngx_http_mruby_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);
  ngx_int_t rc;
  ngx_chain_t out;
  ngx_buf_t *b;
  mrb_value body;

  mrb_get_args(mrb, "o", &body);
  if (mrb_type(body) != MRB_TT_STRING) {
    body = mrb_funcall(mrb, body, "to_s", 0, NULL);
  }

  ctx->body = (u_char *)mrb_str_to_cstr(mrb, body);
  ctx->body_length = ngx_strlen(ctx->body);

  b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
  if (b == NULL) {
    ngx_log_error(NGX_LOG_ERR
      , r->connection->log
      , 0
      , "failed to allocate memory from r->pool %s:%d"
      , __FUNCTION__
      , __LINE__
    );
    return mrb_fixnum_value(NGX_ERROR);
  }
  b->pos = ctx->body;
  b->last = ctx->body + ctx->body_length;
  b->memory = 1;
  b->last_buf = 1;

  out.buf = b;
  out.next = NULL;

  r->headers_out.content_length_n = b->last - b->pos;
  rc = ngx_http_next_header_filter(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    return mrb_fixnum_value(NGX_ERROR);
  }
  return mrb_fixnum_value(ngx_http_next_body_filter(r, &out));
}

void ngx_mrb_filter_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_filter;

  class_filter = mrb_define_class_under(mrb, class, "Filter", mrb->object_class);
  mrb_define_method(mrb, class_filter, "body", ngx_mrb_get_filter_body, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_filter, "body=", ngx_mrb_set_filter_body, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_filter, "output", ngx_mrb_set_filter_body, MRB_ARGS_REQ(1));
}
