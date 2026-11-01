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
#include "ngx_stream_mruby_core.h"

/*
// Starts the code of the stream handler in a new fiber, and returns whether
// it waits, returned (its value in *result) or raised (the exception is
// logged, and mrb->exc is cleared).
*/
ngx_mrb_fiber_outcome_t ngx_stream_mrb_start_fiber(ngx_stream_session_t *s, mrb_state *mrb, struct RProc *proc,
                                                   mrb_value *result);
/*
// The second call of the stream handler while a record of its session waits.
// Returns NGX_DECLINED when no record waits, so the code starts; NGX_DONE when
// the record still waits; NGX_STREAM_OK when worker_shutdown_timeout ended
// the wait (c->close); NGX_ERROR when the record ended; and NGX_OK when the
// record was READY and its fiber was resumed, with the outcome in *outcome.
*/
ngx_int_t ngx_stream_mrb_fiber_call_again(ngx_stream_session_t *s, ngx_stream_mruby_ctx_t *ctx, mrb_value *result,
                                          ngx_mrb_fiber_outcome_t *outcome);

void ngx_stream_mrb_async_class_init(mrb_state *mrb, struct RClass *class);

#endif // NGX_STREAM_MRUBY_ASYNC_H
