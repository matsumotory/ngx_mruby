#include "ngx_stream_mruby_core.h"
#include "ngx_stream_mruby_module.h"
#include "ngx_stream_mruby_async.h"

#include <mruby/array.h>
#include <mruby/error.h>
#include <mruby/irep.h>
#include <mruby/opcode.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/string.h>
#include <mruby/hash.h>
#include <mruby/variable.h>
#include <mruby/class.h>
#include "mruby/internal.h"

typedef struct {
  mrb_state *mrb;
  mrb_value *fiber;
  ngx_stream_session_t *s;
  ngx_int_t stream_status;
} ngx_stream_mrb_reentrant_t;

static mrb_value ngx_stream_mrb_run_fiber(mrb_state *mrb, mrb_value *fiber_proc, mrb_value *result)
{
  mrb_value resume_result = mrb_nil_value();
  mrb_value aliving = mrb_false_value();
  mrb_value handler_result = mrb_nil_value();
  ngx_stream_mruby_ctx_t *ctx;
  ngx_stream_mruby_internal_ctx_t *ictx;

  ictx = mrb->ud;
  ctx = ngx_stream_mrb_get_module_ctx(mrb, ictx->s);
  ctx->fiber_proc = fiber_proc;

  resume_result = mrb_funcall(mrb, *fiber_proc, "call", 0, NULL);
  if (mrb->exc) {
    ngx_log_error(NGX_LOG_NOTICE, ictx->s->connection->log, 0, "%s NOTICE %s:%d: fiber got the raise, leave the fiber",
                  MODULE_NAME, __func__, __LINE__);
    return mrb_false_value();
  }

  if (!mrb_array_p(resume_result)) {
    mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(
        mrb, E_RUNTIME_ERROR,
        "_ngx_mrb_prepare_fiber proc must return array included handler_return and fiber alive status"));
    return mrb_false_value();
  }
  aliving = mrb_ary_entry(resume_result, 0);
  handler_result = mrb_ary_entry(resume_result, 1);

  if (!mrb_test(aliving) && result != NULL) {
    *result = handler_result;
  }

  return aliving;
}

mrb_value ngx_stream_mrb_start_fiber(ngx_stream_session_t *s, mrb_state *mrb, struct RProc *rproc, mrb_value *result)
{
  struct RProc *handler_proc;
  mrb_value *fiber_proc;
  ngx_stream_mruby_ctx_t *ctx;

  ctx = ngx_stream_mrb_get_module_ctx(mrb, s);
  ctx->async_handler_result = result;

  handler_proc = mrb_closure_new(mrb, rproc->body.irep);
  fiber_proc = (mrb_value *)ngx_palloc(s->connection->pool, sizeof(mrb_value));
  *fiber_proc =
      mrb_funcall(mrb, mrb_obj_value(mrb->kernel_module), "_ngx_mrb_prepare_fiber", 1, mrb_obj_value(handler_proc));
  if (mrb->exc) {
    ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
                  "%s NOTICE %s:%d: preparing fiber got the raise, leave the fiber", MODULE_NAME, __func__, __LINE__);
    return mrb_false_value();
  }

  return ngx_stream_mrb_run_fiber(mrb, fiber_proc, result);
}

static ngx_int_t ngx_stream_mrb_post_fiber(ngx_stream_mrb_reentrant_t *re, ngx_stream_mruby_ctx_t *ctx)
{
  int ai;
  ai = mrb_gc_arena_save(re->mrb);

  ngx_stream_mruby_internal_ctx_t *ictx = re->mrb->ud;
  ictx->s = re->s;
  ictx->stream_status = re->stream_status;

  if (re->fiber != NULL) {
    if (mrb_test(ngx_stream_mrb_run_fiber(re->mrb, re->fiber, ctx->async_handler_result))) {
      mrb_gc_arena_restore(re->mrb, ai);
      return NGX_DONE;
    } else {
      mrb_gc_unregister(re->mrb, *re->fiber);
      re->fiber = NULL;
    }

    if (re->mrb->exc) {
      ngx_stream_mruby_raise_error(re->mrb, mrb_obj_value(re->mrb->exc), re->s);
      return NGX_ABORT;
    }

  } else {
    ngx_log_error(NGX_LOG_NOTICE, re->s->connection->log, 0, "%s NOTICE %s:%d: unexpected error, fiber missing",
                  MODULE_NAME, __func__, __LINE__);
    return NGX_ABORT;
  }

  mrb_gc_arena_restore(re->mrb, ai);

  if (ictx->stream_status == NGX_DECLINED) {
    re->s->phase_handler++;
    ngx_stream_core_run_phases(re->s);
  }
  return ictx->stream_status;
}

static void ngx_stream_mrb_timer_handler(ngx_event_t *ev)
{
  ngx_stream_mrb_reentrant_t *re;
  ngx_stream_mruby_ctx_t *ctx;

  re = ev->data;
  ctx = ngx_stream_mrb_get_module_ctx(NULL, re->s);

  ngx_stream_mrb_post_fiber(re, ctx);
}

static void ngx_stream_mrb_cleanup_pending_operation(ngx_stream_mruby_ctx_t *ctx)
{
  if (ctx->cleanup) {
    ctx->cleanup(ctx);
    ctx->cleanup = NULL;
  }
}

static void ngx_stream_mrb_async_sleep_cleanup(void *data)
{
  ngx_stream_mruby_ctx_t *ctx = (ngx_stream_mruby_ctx_t *)data;

  if (ctx->sleep.timer_set) {
    ngx_del_timer(&ctx->sleep);
  }
}

static mrb_value ngx_stream_mrb_async_sleep(mrb_state *mrb, mrb_value self)
{
  mrb_int timer;
  u_char *p;
  ngx_stream_mrb_reentrant_t *re;
  ngx_stream_mruby_ctx_t *ctx;
  ngx_stream_mruby_internal_ctx_t *ictx;

  mrb_get_args(mrb, "i", &timer);

  if (timer <= 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "value of the timer must be a positive number");
  }

  ictx = mrb->ud;
  p = ngx_palloc(ictx->s->connection->pool, sizeof(ngx_event_t) + sizeof(ngx_stream_mrb_reentrant_t));
  re = (ngx_stream_mrb_reentrant_t *)(p + sizeof(ngx_event_t));
  re->mrb = mrb;

  re->s = ictx->s;
  re->stream_status = ictx->stream_status;

  ctx = ngx_stream_mrb_get_module_ctx(mrb, ictx->s);
  re->fiber = ctx->fiber_proc;

  // keeps the object from GC when can resume the fiber
  // Don't forget to remove the object using
  // mrb_gc_unregister, otherwise your object will leak
  mrb_gc_register(mrb, *re->fiber);

  ctx->sleep.handler = ngx_stream_mrb_timer_handler;
  ctx->sleep.data = re;
  ctx->sleep.log = ngx_cycle->log;

  ngx_stream_mrb_cleanup_pending_operation(ctx);
  ctx->cleanup = ngx_stream_mrb_async_sleep_cleanup;

  ngx_add_timer(&ctx->sleep, (ngx_msec_t)timer);
  return self;
}
void ngx_stream_mrb_async_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_nginx_async = mrb_define_class_under(mrb, class, "Async", mrb->object_class);
  mrb_define_class_method(mrb, class_nginx_async, "__sleep", ngx_stream_mrb_async_sleep, MRB_ARGS_REQ(1));
}
