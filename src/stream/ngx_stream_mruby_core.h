/*
// ngx_stream_mruby_core.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_STREAM_MRUBY_CORE_H
#define NGX_STREAM_MRUBY_CORE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <mruby.h>

void ngx_stream_mrb_core_class_init(mrb_state *mrb, struct RClass *class);
typedef struct ngx_stream_mruby_ctx_t {
  mrb_state *mrb;
  mrb_value *fiber_proc;
  mrb_value *async_handler_result;
  // the record (ngx_stream_mruby_async.c) that waits in
  // Nginx::Stream::Async.sleep or is READY to resume, or NULL: a session has
  // one record that waits, and its code runs once
  void *sleeping;
} ngx_stream_mruby_ctx_t;

ngx_stream_mruby_ctx_t *ngx_stream_mrb_get_module_ctx(mrb_state *mrb, ngx_stream_session_t *s);
ngx_stream_session_t *ngx_stream_mrb_get_session_or_raise(mrb_state *mrb);

extern ngx_module_t ngx_stream_mruby_module;

#endif // NGX_STREAM_MRUBY_CORE_H
