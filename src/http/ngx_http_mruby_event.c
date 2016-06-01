/*
// ngx_http_mruby_event.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_event.c
*/

#include "ngx_http_mruby_event.h"

#include <mruby.h>
#include <mruby/string.h>

static void ngx_mrb_event_handler(ngx_event_t *ev)
{
  ngx_http_mruby_event_ctx_t *ctx = ev->data;
  ngx_log_error(NGX_LOG_ERR, ctx->r->connection->log, 0, "callback ngx_mrb_event_handler by timer");

  mrb_yield_argv(ctx->mrb, ctx->blk, 0, NULL);
}

static mrb_value ngx_mrb_event_add_timer(mrb_state *mrb, mrb_value self)
{
  mrb_value blk;
  ngx_msec_t time;
  ngx_http_request_t *r = ngx_mrb_get_request();
  ngx_http_mruby_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);

  mrb_get_args(mrb, "i&", &time, &blk);

  ctx->event->again = 1;
  ctx->event->r = r;
  ctx->event->mrb = mrb;
  ctx->event->self = self;
  ctx->event->blk = blk;
  ctx->event->timer.log = r->connection->log;
  ctx->event->timer.data = ctx->event;
  ctx->event->timer.handler = ngx_mrb_event_handler;

  ngx_add_timer(&ctx->event->timer, time);

  return self;
}

static mrb_value ngx_mrb_event_del_timer(mrb_state *mrb, mrb_value self)
{

  ngx_http_request_t *r = ngx_mrb_get_request();
  ngx_http_mruby_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);

  ngx_del_timer(&ctx->event->timer);
  ctx->event->again = 0;

  return self;
}

void ngx_mrb_event_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_event;

  class_event = mrb_define_class_under(mrb, class, "Event", mrb->object_class);
  mrb_define_class_method(mrb, class_event, "add_timer", ngx_mrb_event_add_timer, MRB_ARGS_REQ(2));
  mrb_define_class_method(mrb, class_event, "del_timer", ngx_mrb_event_del_timer, MRB_ARGS_NONE());
}
