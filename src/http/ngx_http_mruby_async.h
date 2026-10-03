/*
// ngx_http_mruby_async.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_ASYNC_H
#define NGX_HTTP_MRUBY_ASYNC_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <mruby.h>

mrb_value ngx_mrb_start_fiber(ngx_http_request_t *r, mrb_state *mrb, struct RProc *proc, mrb_value *result);
mrb_value ngx_mrb_run_fiber(mrb_state *mrb, mrb_value *fiber, mrb_value *result);

void ngx_mrb_async_class_init(mrb_state *mrb, struct RClass *class);

#ifdef NGX_MRUBY_DEBUG_STATS
/* The number of Nginx::Async.sleep timers that are still pending (for Nginx::Debug.stats). */
ngx_int_t ngx_mrb_async_debug_timers(void);
#endif

#endif // NGX_HTTP_MRUBY_ASYNC_H
