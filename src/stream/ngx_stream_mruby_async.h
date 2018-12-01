/*
// ngx_stream_mruby_async.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_stream_mruby_module.c
*/

#ifndef NGX_STREAM_MRUBY_ASYNC_H
#define NGX_STREAM_MRUBY_ASYNC_H

#include <ngx_config.h>
#include <ngx_stream.h>

#include <mruby.h>

mrb_value ngx_stream_mrb_start_fiber(ngx_stream_session_t *s, mrb_state *mrb, struct RProc *proc, mrb_value *result);
void ngx_stream_mrb_async_class_init(mrb_state *mrb, struct RClass *class);

#endif // NGX_STREAM_MRUBY_ASYNC_H
