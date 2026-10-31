#include "ngx_stream_mruby_core.h"
#include "ngx_stream_mruby_module.h"
#include "ngx_stream_mruby_async.h"
#include "../http/ngx_http_mruby_gc_roots.h"

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

static void ngx_stream_mrb_connection_cleanup(void *data);

static mrb_value ngx_stream_mrb_run_fiber(mrb_state *mrb, mrb_value *fiber_proc, mrb_value *result)
{
  mrb_value aliving = mrb_false_value();
  mrb_value handler_result = mrb_nil_value();
  ngx_stream_mruby_ctx_t *ctx;
  ngx_stream_mruby_internal_ctx_t *ictx;

  ictx = mrb->ud;
  ctx = ngx_stream_mrb_get_module_ctx(mrb, ictx->s);
  ctx->fiber_proc = fiber_proc;

  handler_result = mrb_fiber_resume(mrb, *fiber_proc, 0, NULL);
  if (mrb->exc) {
    ngx_log_error(NGX_LOG_NOTICE, ictx->s->connection->log, 0, "%s NOTICE %s:%d: fiber got the raise, leave the fiber",
                  MODULE_NAME, __func__, __LINE__);
    return mrb_false_value();
  }

  aliving = mrb_fiber_alive_p(mrb, *fiber_proc);

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
  ngx_pool_cleanup_t *cln;

  ctx = ngx_stream_mrb_get_module_ctx(mrb, s);
  ctx->async_handler_result = result;
  ctx->mrb = mrb;

  // When the connection pool is destroyed, cancel a still-armed
  // Nginx::Stream::Async.sleep timer and drop the fiber from the GC root, so
  // that a session whose pool is freed while the sleep is still pending (a
  // worker shutting down or a configuration reload, or a connection timeout)
  // does not leave the timer to fire on the freed pool and read freed memory.
  // (A client that closes during the sleep does not reach this: nginx defers
  // the close until the handler resumes.) The HTTP path has the same guard
  // (ngx_mrb_fiber_cleanup and the ngx_http_cleanup_add in ngx_mrb_async_sleep).
  // Registering it again for a second handler of the same session is harmless:
  // ngx_stream_mrb_connection_cleanup is idempotent.
  cln = ngx_pool_cleanup_add(s->connection->pool, 0);
  if (cln == NULL) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%s ERROR %s:%d: failed to allocate the fiber cleanup",
                  MODULE_NAME, __func__, __LINE__);
    return mrb_false_value();
  }
  cln->handler = ngx_stream_mrb_connection_cleanup;
  cln->data = ctx;

  handler_proc = rproc;
  handler_proc->upper = NULL;
  handler_proc->e.target_class = mrb->object_class;
  fiber_proc = (mrb_value *)ngx_palloc(s->connection->pool, sizeof(mrb_value));
  *fiber_proc = mrb_fiber_new(mrb, rproc);
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
  // re->s is the current session only until this function returns
  ngx_stream_session_t *prev_s = ictx->s;
  ictx->s = re->s;
  ictx->stream_status = re->stream_status;

  if (re->fiber != NULL) {
    if (mrb_test(ngx_stream_mrb_run_fiber(re->mrb, re->fiber, ctx->async_handler_result))) {
      mrb_gc_arena_restore(re->mrb, ai);
      ictx->s = prev_s;
      return NGX_DONE;
    } else {
      if (ctx->fiber_slot != NGX_MRB_GC_ROOTS_NONE) {
        ngx_mrb_gc_roots_remove(re->mrb, ctx->fiber_slot);
        ctx->fiber_slot = NGX_MRB_GC_ROOTS_NONE;
      }
      re->fiber = NULL;
    }

    if (re->mrb->exc) {
      ngx_stream_mruby_raise_error(re->mrb, mrb_obj_value(re->mrb->exc), re->s);
      // all sessions of the stream {} block share this mrb_state: clear the
      // exception and restore the arena as ngx_stream_mruby_handler does, or
      // ngx_stream_mrb_start_fiber finds the exception in the next session
      // and aborts that session with it
      re->mrb->exc = NULL;
      mrb_gc_arena_restore(re->mrb, ai);
      ictx->s = prev_s;
      return NGX_ABORT;
    }

  } else {
    ngx_log_error(NGX_LOG_NOTICE, re->s->connection->log, 0, "%s NOTICE %s:%d: unexpected error, fiber missing",
                  MODULE_NAME, __func__, __LINE__);
    ictx->s = prev_s;
    return NGX_ABORT;
  }

  mrb_gc_arena_restore(re->mrb, ai);
  ictx->s = prev_s;

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
  ngx_stream_session_t *s;
  ngx_stream_core_main_conf_t *cmcf;
  ngx_int_t rc;

  re = ev->data;
  // re is allocated from the connection pool, which the finalization below
  // destroys
  s = re->s;
  ctx = ngx_stream_mrb_get_module_ctx(NULL, s);

  rc = ngx_stream_mrb_post_fiber(re, ctx);

  /*
   * The checker of the access phase (ngx_stream_core_generic_phase) got the
   * NGX_DONE of ngx_stream_mruby_handler when the fiber first waited, so the
   * result of the code after the sleep is handled here, as that checker
   * handles the result of a handler that does not wait.
   * ngx_stream_mrb_post_fiber has run the phases for NGX_DECLINED already, and
   * NGX_DONE means that the fiber waits again.
   */
  if (rc == NGX_DECLINED || rc == NGX_DONE || rc == NGX_AGAIN) {
    return;
  }

  if (rc == NGX_OK) {
    cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);
    s->phase_handler = cmcf->phase_engine.handlers[s->phase_handler].next;
    ngx_stream_core_run_phases(s);
    return;
  }

  if (rc == NGX_ERROR) {
    rc = NGX_STREAM_INTERNAL_SERVER_ERROR;
  }

  ngx_stream_finalize_session(s, rc);
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

// Runs from the connection pool cleanup registered in
// ngx_stream_mrb_start_fiber, when the session ends. It cancels a pending
// Async.sleep timer (through the sleep cleanup) so the timer does not fire on
// the freed pool, and it drops the fiber from the GC root so the fiber does
// not stay protected for the worker's life after the session is gone. It is
// idempotent: the pool runs it before it frees ctx, *ctx->fiber_proc and the
// sleep event, and a second registration for the same session finds nothing
// left to do.
static void ngx_stream_mrb_connection_cleanup(void *data)
{
  ngx_stream_mruby_ctx_t *ctx = (ngx_stream_mruby_ctx_t *)data;

  ngx_stream_mrb_cleanup_pending_operation(ctx);

  if (ctx->fiber_slot != NGX_MRB_GC_ROOTS_NONE) {
    ngx_mrb_gc_roots_remove(ctx->mrb, ctx->fiber_slot);
    ctx->fiber_slot = NGX_MRB_GC_ROOTS_NONE;
  }
}

static mrb_value ngx_stream_mrb_async_sleep(mrb_state *mrb, mrb_value self)
{
  mrb_int timer;
  u_char *p;
  ngx_stream_mrb_reentrant_t *re;
  ngx_stream_mruby_ctx_t *ctx;
  ngx_stream_mruby_internal_ctx_t *ictx;
  ngx_stream_session_t *s;

  mrb_get_args(mrb, "i", &timer);

  if (timer <= 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "value of the timer must be a positive number");
  }

  s = ngx_stream_mrb_get_session_or_raise(mrb);
  ictx = mrb->ud;
  p = ngx_palloc(s->connection->pool, sizeof(ngx_event_t) + sizeof(ngx_stream_mrb_reentrant_t));
  re = (ngx_stream_mrb_reentrant_t *)(p + sizeof(ngx_event_t));
  re->mrb = mrb;

  re->s = s;
  re->stream_status = ictx->stream_status;

  ctx = ngx_stream_mrb_get_module_ctx(mrb, s);
  re->fiber = ctx->fiber_proc;

  // Keep the fiber from GC while it can be resumed. Register it once: a fiber
  // that sleeps more than once reuses this registration, and
  // ngx_stream_mrb_connection_cleanup or ngx_stream_mrb_post_fiber removes it
  // exactly once (when the session ends, or when the fiber finishes).
  if (ctx->fiber_slot == NGX_MRB_GC_ROOTS_NONE) {
    ctx->fiber_slot = ngx_mrb_gc_roots_add(mrb, *re->fiber);
  }

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
