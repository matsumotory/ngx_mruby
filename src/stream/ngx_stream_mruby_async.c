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
// first member, the fiber. A stream session can start more than one fiber (a
// second UDP datagram from the same client runs the handler again while a
// fiber of the same session still sleeps), so the slot in the GC root holder,
// the timer and the owner hook are kept per fiber. The fiber takes the slot
// and adds the owner hook, a connection pool cleanup, when it first sleeps
// (ngx_stream_mrb_async_sleep). The slot is freed once: when the fiber ends
// (normally or with an exception) or when the connection pool is destroyed
// while it is still suspended (ngx_stream_mrb_fiber_cleanup). sleep is the
// data of the resume of its sleep.
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

  outcome = ngx_mrb_fiber_resume(&f->base, result, ngx_stream_mrb_fiber_log_raise, ictx->s);
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

static ngx_int_t ngx_stream_mrb_post_fiber(ngx_stream_mrb_reentrant_t *re, ngx_stream_mruby_ctx_t *ctx)
{
  int ai;
  ngx_mrb_fiber_outcome_t outcome;
  ai = mrb_gc_arena_save(re->mrb);

  ngx_stream_mruby_internal_ctx_t *ictx = re->mrb->ud;
  // re->s is the current session only until this function returns
  ngx_stream_session_t *prev_s = ictx->s;
  ictx->s = re->s;
  ictx->stream_status = re->stream_status;

  if (re->fiber != NULL) {
    outcome = ngx_stream_mrb_run_fiber(re->mrb, re->fiber, ctx->async_handler_result);
    if (outcome == NGX_MRB_FIBER_WAITS) {
      mrb_gc_arena_restore(re->mrb, ai);
      ictx->s = prev_s;
      return NGX_DONE;
    }

    // the fiber has ended and holds no slot in the GC root holder any more
    re->fiber = NULL;

    if (outcome == NGX_MRB_FIBER_RAISED) {
      // ngx_mrb_fiber_resume has logged the exception and cleared mrb->exc,
      // which all sessions of the stream {} block share
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
  ngx_stream_mrb_fiber_t *f;
  ngx_stream_mruby_ctx_t *ctx;
  ngx_stream_session_t *s;
  ngx_stream_core_main_conf_t *cmcf;
  ngx_int_t rc;

  re = ev->data;
  f = (ngx_stream_mrb_fiber_t *)re->fiber;
  ngx_mrb_fiber_timer_fired(&f->base);
  if (f->ctx->sleeping == f) {
    f->ctx->sleeping = NULL;
  }

  // re is allocated from the connection pool, which the finalization below
  // destroys
  s = re->s;
  ctx = f->ctx;

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
  ngx_stream_mrb_fiber_t *f, *other;
  ngx_pool_cleanup_t *cln;

  mrb_get_args(mrb, "i", &timer);

  if (timer <= 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "value of the timer must be a positive number");
  }

  s = ngx_stream_mrb_get_session_or_raise(mrb);
  ictx = mrb->ud;
  ctx = ngx_stream_mrb_get_module_ctx(mrb, s);
  f = (ngx_stream_mrb_fiber_t *)ctx->fiber_proc;
  if (f == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "Nginx::Stream::Async.sleep is not available without a handler fiber");
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

  // A session has one pending sleep: a sleep of another fiber of the session
  // (a second UDP datagram) replaces the pending one, whose fiber is then not
  // resumed and keeps its slot until the session ends.
  other = ctx->sleeping;
  if (other != NULL && other != f) {
    ngx_mrb_fiber_delete_timer(&other->base);
  }
  ctx->sleeping = f;

  ngx_mrb_fiber_arm_timer(&f->base, (ngx_msec_t)timer, ngx_stream_mrb_timer_handler, re);
  return self;
}
void ngx_stream_mrb_async_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_nginx_async = mrb_define_class_under(mrb, class, "Async", mrb->object_class);
  mrb_define_class_method(mrb, class_nginx_async, "__sleep", ngx_stream_mrb_async_sleep, MRB_ARGS_REQ(1));
}
