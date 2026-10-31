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

// The fiber of a stream handler, allocated from the connection pool. It is
// registered with mrb_gc_register once, when it is created in
// ngx_stream_mrb_start_fiber, and unregistered once: when it ends (normally or
// with an exception) or when the connection pool is destroyed while it is still
// suspended. ctx->fiber_proc and re->fiber point to the first member, so a
// mrb_value * to the fiber is also an ngx_stream_mrb_fiber_t *. A stream
// session can start more than one fiber (a second UDP datagram re-runs the
// handler while a previous fiber of the same session still sleeps), so the
// GC-root state is tracked per fiber here, not once per session.
typedef struct {
  mrb_value fiber;
  mrb_state *mrb;
  ngx_flag_t registered;
  ngx_stream_mruby_ctx_t *ctx;
} ngx_stream_mrb_fiber_t;

static void ngx_stream_mrb_fiber_cleanup(void *data);

static void ngx_stream_mrb_fiber_unregister(mrb_value *fiber_proc)
{
  ngx_stream_mrb_fiber_t *f = (ngx_stream_mrb_fiber_t *)fiber_proc;

  if (f->registered) {
    f->registered = 0;
    mrb_gc_unregister(f->mrb, f->fiber);
  }
}

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
    ngx_stream_mrb_fiber_unregister(fiber_proc);
    return mrb_false_value();
  }

  aliving = mrb_fiber_alive_p(mrb, *fiber_proc);

  if (!mrb_test(aliving)) {
    ngx_stream_mrb_fiber_unregister(fiber_proc);
    if (result != NULL) {
      *result = handler_result;
    }
  }

  return aliving;
}

mrb_value ngx_stream_mrb_start_fiber(ngx_stream_session_t *s, mrb_state *mrb, struct RProc *rproc, mrb_value *result)
{
  struct RProc *handler_proc;
  mrb_value *fiber_proc;
  ngx_stream_mrb_fiber_t *f;
  ngx_stream_mruby_ctx_t *ctx;
  ngx_pool_cleanup_t *cln;

  ctx = ngx_stream_mrb_get_module_ctx(mrb, s);
  ctx->async_handler_result = result;
  ctx->mrb = mrb;

  handler_proc = rproc;
  handler_proc->upper = NULL;
  handler_proc->e.target_class = mrb->object_class;

  // A stream session can start more than one fiber: a second UDP datagram from
  // the same client re-runs the handler while a previous fiber of the session
  // is still suspended in Nginx::Stream::Async.sleep. Each fiber has its own
  // ngx_stream_mrb_fiber_t, so its GC-root state is tracked on its own struct
  // and a later fiber is kept from GC even while an earlier one of the same
  // session is. ngx_stream_mrb_fiber_cleanup runs when the connection pool is
  // destroyed with the fiber still suspended (a worker shutting down or a
  // configuration reload, or a connection timeout, or another datagram ending
  // the session); it cancels a still-armed sleep timer so the timer does not
  // fire on the freed pool and read freed memory, and drops the fiber from the
  // GC root.
  f = ngx_pcalloc(s->connection->pool, sizeof(ngx_stream_mrb_fiber_t));
  cln = ngx_pool_cleanup_add(s->connection->pool, 0);
  if (f == NULL || cln == NULL) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%s ERROR %s:%d: failed to allocate the fiber", MODULE_NAME,
                  __func__, __LINE__);
    return mrb_false_value();
  }
  f->mrb = mrb;
  f->ctx = ctx;
  fiber_proc = &f->fiber;

  *fiber_proc = mrb_fiber_new(mrb, rproc);
  if (mrb->exc) {
    ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
                  "%s NOTICE %s:%d: preparing fiber got the raise, leave the fiber", MODULE_NAME, __func__, __LINE__);
    return mrb_false_value();
  }

  // Keep the fiber from GC while it can be resumed. Registered once here, per
  // fiber; ngx_stream_mrb_run_fiber drops it when the fiber ends, and
  // ngx_stream_mrb_fiber_cleanup when the connection pool is destroyed first.
  mrb_gc_register(mrb, *fiber_proc);
  f->registered = 1;
  cln->handler = ngx_stream_mrb_fiber_cleanup;
  cln->data = f;

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
      // ngx_stream_mrb_run_fiber has dropped the finished fiber from the GC root
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

// Runs from the per-fiber connection pool cleanup registered in
// ngx_stream_mrb_start_fiber, when the connection pool is destroyed with the
// fiber still suspended (a worker shutting down or a configuration reload, or a
// connection timeout, or another datagram of the same UDP session ending it).
// It cancels a pending Async.sleep timer (through the sleep cleanup) so the
// timer does not fire on the freed pool and read freed memory, and it drops the
// fiber from the GC root so it does not stay protected for the worker's life
// after the session is gone. A client that closes during a TCP sleep does not
// reach the freed-timer path: nginx defers the close until the handler resumes.
// The pool runs the cleanups before it frees ctx, the fiber struct and the
// sleep event; cancelling the single ctx->sleep timer again from another
// fiber's cleanup of the same session is idempotent.
static void ngx_stream_mrb_fiber_cleanup(void *data)
{
  ngx_stream_mrb_fiber_t *f = (ngx_stream_mrb_fiber_t *)data;

  ngx_stream_mrb_cleanup_pending_operation(f->ctx);
  ngx_stream_mrb_fiber_unregister(&f->fiber);
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
  // The fiber is already a GC root from ngx_stream_mrb_start_fiber (per fiber),
  // so a second datagram's fiber of the same session is kept from GC too.
  re->fiber = ctx->fiber_proc;

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
