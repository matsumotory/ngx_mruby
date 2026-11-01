/*
// ngx_stream_mruby_async.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_stream_mruby_module.c
*/

#ifndef NGX_STREAM_MRUBY_ASYNC_H
#define NGX_STREAM_MRUBY_ASYNC_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <mruby.h>

#include "../common/ngx_mruby_fiber.h"

/*
// Starts the code of the stream handler in a new fiber, and returns whether
// it waits, returned (its value in *result) or raised (the exception is
// logged, and mrb->exc is cleared).
*/
ngx_mrb_fiber_outcome_t ngx_stream_mrb_start_fiber(ngx_stream_session_t *s, mrb_state *mrb, struct RProc *proc,
                                                   mrb_value *result);
void ngx_stream_mrb_async_class_init(mrb_state *mrb, struct RClass *class);

#endif // NGX_STREAM_MRUBY_ASYNC_H
