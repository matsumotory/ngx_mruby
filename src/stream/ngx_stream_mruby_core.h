/*
// ngx_stream_mruby_core.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_STREAM_MRUBY_CORE_H
#define NGX_STREAM_MRUBY_CORE_H

#include <ngx_config.h>
#include <ngx_stream.h>

#include <mruby.h>

void ngx_stream_mrb_core_class_init(mrb_state *mrb, struct RClass *class);
typedef void (*ngx_stream_mrb_cleanup_pt)(void *data);
typedef struct ngx_stream_mruby_ctx_t {
  mrb_value *fiber_proc;
  mrb_value *async_handler_result;
  ngx_stream_mrb_cleanup_pt cleanup;
  ngx_event_t sleep;
} ngx_stream_mruby_ctx_t;

ngx_stream_mruby_ctx_t *ngx_stream_mrb_get_module_ctx(mrb_state *mrb, ngx_stream_session_t *s);

extern ngx_module_t ngx_stream_mruby_module;

#endif // NGX_STREAM_MRUBY_CORE_H
