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

typedef struct {
  mrb_state *mrb;
  mrb_value *fiber;
  ngx_stream_session_t *s;
  ngx_int_t stream_status;
} ngx_stream_mrb_reentrant_t;

// The record of a stream handler's fiber, allocated from the connection pool
// for each run of the handler (the common part is in
// src/common/ngx_mruby_fiber.h). ctx->fiber_proc and re->fiber point to its
// first member, the fiber. A session runs its code once (Q4 of section 9 of
// docs/proposals/core-stabilization.md): while the record waits
// (ctx->sleeping), nginx calling the handler again, for another datagram of
// a UDP session, does not start the code again. The fiber takes the slot and
// adds the owner hook, a connection pool cleanup, when it first sleeps
// (ngx_stream_mrb_async_sleep). The slot is freed once: when the fiber ends
// (normally or with an exception) or when the connection pool is destroyed
// while it is still suspended (ngx_stream_mrb_fiber_cleanup). sleep is the
// data of the resume of its sleep, with the result that the code had set
// when it started to sleep.
typedef struct {
  ngx_mrb_fiber_t base;
  ngx_stream_mrb_reentrant_t sleep;
  ngx_stream_mruby_ctx_t *ctx;
} ngx_stream_mrb_fiber_t;

static void ngx_stream_mrb_fiber_log_raise(mrb_state *mrb, mrb_value exc, void *data)
{
  ngx_stream_mruby_raise_error(mrb, exc, data);
}

static ngx_mrb_fiber_outcome_t ngx_stream_mrb_run_fiber(mrb_state *mrb, mrb_value *fiber_proc, mrb_value *result)
{
  ngx_stream_mrb_fiber_t *f = (ngx_stream_mrb_fiber_t *)fiber_proc;
  ngx_stream_mruby_ctx_t *ctx;
  ngx_stream_mruby_internal_ctx_t *ictx;
  ngx_mrb_fiber_outcome_t outcome;

  ictx = mrb->ud;
  ctx = ngx_stream_mrb_get_module_ctx(mrb, ictx->s);
  ctx->fiber_proc = fiber_proc;

  outcome = ngx_mrb_fiber_resume(&f->base, NULL, result, ngx_stream_mrb_fiber_log_raise, ictx->s);
  if (outcome == NGX_MRB_FIBER_REFUSED) {
    // the record has ended: the session ends as after an exception
    ngx_log_error(NGX_LOG_ERR, ictx->s->connection->log, 0,
                  "%s ERROR %s:%d: the fiber is not resumed: its handler has ended", MODULE_NAME, __func__, __LINE__);
    return NGX_MRB_FIBER_RAISED;
  }
  if (outcome == NGX_MRB_FIBER_RAISED) {
    ngx_log_error(NGX_LOG_NOTICE, ictx->s->connection->log, 0, "%s NOTICE %s:%d: fiber got the raise, leave the fiber",
                  MODULE_NAME, __func__, __LINE__);
  }

  return outcome;
}

ngx_mrb_fiber_outcome_t ngx_stream_mrb_start_fiber(ngx_stream_session_t *s, mrb_state *mrb, struct RProc *rproc,
                                                   mrb_value *result)
{
  ngx_stream_mrb_fiber_t *f;
  ngx_stream_mruby_ctx_t *ctx;

  ctx = ngx_stream_mrb_get_module_ctx(mrb, s);
  ctx->async_handler_result = result;
  ctx->mrb = mrb;

  // A run that never sleeps takes no slot in the GC root holder and adds no
  // cleanup. The RProc of the code is prepared once, when the code is
  // compiled (ngx_mrb_fiber_prepare_proc).
  f = ngx_pcalloc(s->connection->pool, sizeof(ngx_stream_mrb_fiber_t));
  if (f == NULL) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%s ERROR %s:%d: failed to allocate the fiber", MODULE_NAME,
                  __func__, __LINE__);
    return NGX_MRB_FIBER_RETURNED;
  }
  ngx_mrb_fiber_init(&f->base, mrb, NGX_MRB_FIBER_STREAM);
  f->ctx = ctx;

  f->base.fiber = mrb_fiber_new(mrb, rproc);
  if (mrb->exc) {
    ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
                  "%s NOTICE %s:%d: preparing fiber got the raise, leave the fiber", MODULE_NAME, __func__, __LINE__);
    f->base.state = NGX_MRB_FIBER_FAILED;
    ngx_stream_mruby_raise_error(mrb, mrb_obj_value(mrb->exc), s);
    mrb->exc = NULL;
    return NGX_MRB_FIBER_RAISED;
  }

  return ngx_stream_mrb_run_fiber(mrb, &f->base.fiber, result);
}

/*
 * The wake (section 4.4 of docs/proposals/core-stabilization.md): the record
 * becomes READY and the phases of the session run again, as nginx runs them
 * for a read event. The checker of the access phase calls the mruby handler
 * again (s->phase_handler did not move), which resumes the fiber
 * (ngx_stream_mrb_fiber_call_again) and returns the result of the code to
 * the checker, as a handler that did not wait does.
 */
static void ngx_stream_mrb_timer_handler(ngx_event_t *ev)
{
  ngx_stream_mrb_reentrant_t *re;
  ngx_stream_mrb_fiber_t *f;

  re = ev->data;
  f = (ngx_stream_mrb_fiber_t *)re->fiber;
  ngx_mrb_fiber_timer_fired(&f->base);

  if (f->base.state != NGX_MRB_FIBER_WAITING || f->ctx->sleeping != f) {
    // The code called Nginx::Stream::Async.__sleep without the Fiber.yield
    // of Nginx::Stream::Async.sleep, so its record did not wait (or has
    // ended since); the owner hook deletes the timer of a cancelled record.
    // Nothing is resumed.
    ngx_log_error(NGX_LOG_ERR, re->s->connection->log, 0,
                  "%s ERROR %s:%d: the timer fired for a fiber that does not wait", MODULE_NAME, __func__, __LINE__);
    return;
  }

  f->base.state = NGX_MRB_FIBER_READY;
  ngx_stream_core_run_phases(re->s);
}

ngx_int_t ngx_stream_mrb_fiber_call_again(ngx_stream_session_t *s, ngx_stream_mruby_ctx_t *ctx, mrb_value *result,
                                          ngx_mrb_fiber_outcome_t *outcome)
{
  ngx_stream_mrb_fiber_t *f = ctx->sleeping;
  ngx_stream_mruby_internal_ctx_t *ictx;

  if (f == NULL) {
    return NGX_DECLINED;
  }

  switch (f->base.state) {
  case NGX_MRB_FIBER_WAITING:
    if (s->connection->close) {
      // worker_shutdown_timeout expired: nginx set c->close and called the
      // read handler. The wait ends, and so does the session, as
      // ngx_stream_proxy_module ends its sessions then.
      ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "shutdown timeout");
      ctx->sleeping = NULL;
      // the owner hook stays on the list of the connection pool, and runs
      // again when the pool is destroyed: by then the timer is deleted and
      // the slot is freed, and it finds nothing to do
      ngx_mrb_fiber_cancel(&f->base);
      return NGX_STREAM_OK;
    }
    // nginx ran the phases while the record waits, for example for another
    // datagram of a UDP session: the code does not start again (Q4)
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "%s INFO %s:%d: the handler waits; its code is not run again",
                  MODULE_NAME, __func__, __LINE__);
    return NGX_DONE;

  case NGX_MRB_FIBER_READY:
    ctx->sleeping = NULL;
    // the result that the code had set when it started to sleep
    ictx = f->base.mrb->ud;
    ictx->stream_status = f->sleep.stream_status;
    *outcome = ngx_stream_mrb_run_fiber(f->base.mrb, &f->base.fiber, result);
    return NGX_OK;

  default:
    ctx->sleeping = NULL;
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%s ERROR %s:%d: the handler of the session has ended",
                  MODULE_NAME, __func__, __LINE__);
    return NGX_ERROR;
  }
}

// The owner hook of a record, a connection pool cleanup that the fiber adds
// when it first sleeps. It runs when the session ends: a worker shutting
// down or a configuration reload, or another datagram of the same UDP
// session ending it. It deletes a pending timer, so that the timer does not
// fire on the freed pool and read freed memory, and frees the fiber's slot
// in the GC root holder, so that the fiber does not stay protected for the
// worker's life after the session is gone. (A client that closes a TCP
// session during the sleep does not reach this: nginx defers the close until
// the handler resumes.) The pool runs it before it frees ctx and the record.
static void ngx_stream_mrb_fiber_cleanup(void *data)
{
  ngx_stream_mrb_fiber_t *f = (ngx_stream_mrb_fiber_t *)data;

  if (f->ctx->sleeping == f) {
    f->ctx->sleeping = NULL;
  }
  ngx_mrb_fiber_cancel(&f->base);
}

static mrb_value ngx_stream_mrb_async_sleep(mrb_state *mrb, mrb_value self)
{
  mrb_int timer;
  ngx_stream_mrb_reentrant_t *re;
  ngx_stream_mruby_ctx_t *ctx;
  ngx_stream_mruby_internal_ctx_t *ictx;
  ngx_stream_session_t *s;
  ngx_stream_mrb_fiber_t *f;
  ngx_pool_cleanup_t *cln;

  mrb_get_args(mrb, "i", &timer);

  if (timer <= 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "value of the timer must be a positive number");
  }

  s = ngx_stream_mrb_get_session_or_raise(mrb);
  ictx = mrb->ud;
  ctx = ngx_stream_mrb_get_module_ctx(mrb, s);
  f = (ngx_stream_mrb_fiber_t *)ctx->fiber_proc;
  // Only the fiber that runs now can wait, not one that has ended (Ruby code
  // that runs for it after its end, such as the inspect of its exception).
  if (f == NULL || f->base.state != NGX_MRB_FIBER_RUNNING) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "Nginx::Stream::Async.sleep is not available without a running handler fiber");
  }

  // The owner hook and the slot come first, so that a failure there raises
  // with no timer armed. A fiber that sleeps more than once keeps its slot
  // and its hook.
  if (!f->base.hooked) {
    cln = ngx_pool_cleanup_add(s->connection->pool, 0);
    if (cln == NULL) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_pool_cleanup_add failed");
    }
    cln->handler = ngx_stream_mrb_fiber_cleanup;
    cln->data = f;
    f->base.hooked = 1;
  }
  if (ngx_mrb_fiber_hold(&f->base) != NGX_OK) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "failed to keep the fiber of the handler from the GC");
  }

  re = &f->sleep;
  re->mrb = mrb;
  re->s = s;
  re->stream_status = ictx->stream_status;
  re->fiber = &f->base.fiber;

  // the record that waits for the session, which the handler finds when
  // nginx calls it again (ngx_stream_mrb_fiber_call_again)
  ctx->sleeping = f;

  ngx_mrb_fiber_arm_timer(&f->base, (ngx_msec_t)timer, ngx_stream_mrb_timer_handler, re);
  return self;
}
void ngx_stream_mrb_async_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_nginx_async = mrb_define_class_under(mrb, class, "Async", mrb->object_class);
  mrb_define_class_method(mrb, class_nginx_async, "__sleep", ngx_stream_mrb_async_sleep, MRB_ARGS_REQ(1));
}
