/*
// ngx_http_mruby_async.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_async.h"

#include "ngx_http_mruby_core.h"
#include "ngx_http_mruby_gc_roots.h"
#include "ngx_http_mruby_module.h"
#include "ngx_http_mruby_request.h"
#include "ngx_http_mruby_var.h"

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
  ngx_http_request_t *r;
  ngx_uint_t fiber_prev_status;
  ngx_http_request_t *sr;
} ngx_mrb_reentrant_t;

// The data of the post handler of a subrequest: the record that waits for it
// (record), and done once the first call of the post handler copied the
// response. re is the data of the resume of the old path (ngx_mrb_post_fiber)
typedef struct {
  ngx_mrb_reentrant_t *re;
  ngx_str_t *uri;
  ngx_http_mrb_fiber_t *record;
  unsigned done : 1;
} ngx_mrb_async_http_ctx_t;

/*
 * The record of a handler's fiber, allocated from the request pool for each
 * run of a handler (the common part is in src/common/ngx_mruby_fiber.h).
 * ctx->fiber_proc and re->fiber point to its first member, the fiber.
 *
 * - kind is the handler that runs the fiber, also when a timer or a
 *   subrequest resumes it.
 * - sleep is the data of the resume of Nginx::Async.sleep, for the one timer
 *   of the record; the record keeps it because it waits for one timer or one
 *   subrequest at a time. sleep.r is the request that the record runs for,
 *   from the start of the run.
 * - posted is the entry of the posted request of the wake, allocated at the
 *   first wait (ngx_http_mrb_fiber_prepare_wait), so that a run that never
 *   waits does not carry it.
 * - result is the result that the code set (Nginx.return,
 *   Nginx.send_header, Nginx.status_code=, Nginx.redirect with a URL), when
 *   has_result is set: the result of a handler is its own, not one that an
 *   earlier handler of the request stored (Q6 of section 9 of
 *   docs/proposals/core-stabilization.md).
 * - wake is set when the fiber waits for nginx to call its handler again
 *   (ngx_http_mrb_fiber_wait_on_nginx): the timer then only marks the record
 *   READY and posts the request with posted, and the end of a subrequest
 *   only marks it READY (nginx wakes the parent itself). Without it, the
 *   timer or the end of the subrequest resumes the fiber itself
 *   (ngx_mrb_post_fiber), as for a fiber that waits in a location that
 *   Nginx.redirect runs from Ruby code.
 */
struct ngx_http_mrb_fiber_s {
  ngx_mrb_fiber_t base;
  ngx_http_mruby_handler_kind_t kind;
  // next to kind, in the space that the alignment of sleep leaves;
  // has_response: the post handler of a subrequest copied the response, and
  // the next resume passes it to the fiber
  unsigned has_result : 1;
  unsigned wake : 1;
  unsigned has_response : 1;
  ngx_mrb_reentrant_t sleep;
  ngx_http_posted_request_t *posted;
  ngx_int_t result;
};

/*
 * The record whose fiber runs now, set by ngx_mrb_run_fiber for the time the
 * fiber runs and restored afterwards, so that it is right also while a
 * handler runs inside another one (in the location that Nginx.redirect runs
 * from Ruby code). Nginx.return stores the result there.
 */
static ngx_http_mrb_fiber_t *ngx_http_mrb_running;

static ngx_mrb_fiber_outcome_t ngx_mrb_run_fiber(mrb_state *mrb, mrb_value *fiber_proc, mrb_value *result);
static void ngx_http_mrb_wait_handler(ngx_http_request_t *r);
static mrb_value ngx_mrb_async_http_response_body(mrb_state *mrb, void *data);

// Whether Nginx::Async may suspend the fiber of this kind of handler. nginx
// resumes it for mruby_set and the post_read, server_rewrite, rewrite,
// access and content handlers (see ngx_http_mruby_handler_kind_t).
static ngx_flag_t ngx_mrb_handler_can_wait(ngx_http_mruby_handler_kind_t kind)
{
  switch (kind) {
  case NGX_HTTP_MRUBY_HANDLER_SET:
  case NGX_HTTP_MRUBY_HANDLER_POST_READ:
  case NGX_HTTP_MRUBY_HANDLER_SERVER_REWRITE:
  case NGX_HTTP_MRUBY_HANDLER_REWRITE:
  case NGX_HTTP_MRUBY_HANDLER_ACCESS:
  case NGX_HTTP_MRUBY_HANDLER_CONTENT:
    return 1;
  default:
    return 0;
  }
}

// The name of a handler that cannot wait, for messages.
static const char *ngx_mrb_handler_kind_name(ngx_http_mruby_handler_kind_t kind)
{
  switch (kind) {
  case NGX_HTTP_MRUBY_HANDLER_LOG:
    return "a log handler";
  case NGX_HTTP_MRUBY_HANDLER_HEADER_FILTER:
    return "a header filter";
  case NGX_HTTP_MRUBY_HANDLER_BODY_FILTER:
    return "a body filter";
  default:
    return "a context without a request handler";
  }
}

/*
 * Returns the current request, or raises a RuntimeError when there is no
 * current request or the handler that runs now cannot wait.
 * Nginx::Async.sleep and Nginx::Async::HTTP.sub_request call it before they
 * arm a timer or post a subrequest, so a refused call leaves nothing behind
 * that could touch the request later.
 */
static ngx_http_request_t *ngx_mrb_async_request(mrb_state *mrb, const char *method)
{
  ngx_http_request_t *r;
  ngx_http_mruby_ctx_t *ctx;

  r = ngx_mrb_get_request_or_raise(mrb);
  ctx = ngx_mrb_http_get_module_ctx(mrb, r);
  if (!ngx_mrb_handler_can_wait(ctx->handler_kind)) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "%s is not available in %s", method, ngx_mrb_handler_kind_name(ctx->handler_kind));
  }

  return r;
}

// The owner hook of a record: a request cleanup of the main request, which
// nginx runs when it terminates the request and before it frees the request
// pool. It deletes a pending timer, so that the timer never fires on a freed
// pool, and frees the slot of a fiber that still waits.
static void ngx_http_mrb_fiber_owner_cleanup(void *data)
{
  ngx_mrb_fiber_cancel(data);
}

/*
 * Prepares the first and every later wait of the fiber that runs now, before
 * the wait is armed: the owner hook once, then the slot in the GC root
 * holder. Returns the record, or raises without arming anything.
 */
static ngx_http_mrb_fiber_t *ngx_http_mrb_fiber_prepare_wait(mrb_state *mrb, ngx_http_request_t *r,
                                                             ngx_http_mruby_ctx_t *ctx)
{
  ngx_http_mrb_fiber_t *f = (ngx_http_mrb_fiber_t *)ctx->fiber_proc;
  ngx_http_cleanup_t *cln;

  // Only the fiber that runs now can wait. Ruby code that runs for the
  // record after its fiber ended (the inspect of its exception, for example)
  // finds it in another state.
  if (f == NULL || f->base.state != NGX_MRB_FIBER_RUNNING) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "Nginx::Async is not available without a running handler fiber");
  }

  if (!f->base.hooked) {
    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_http_cleanup_add failed");
    }
    cln->handler = ngx_http_mrb_fiber_owner_cleanup;
    cln->data = &f->base;
    f->base.hooked = 1;
  }

  // the entry of the posted request of the wake (ngx_http_mrb_fiber_wake),
  // once per record
  if (f->posted == NULL) {
    f->posted = ngx_palloc(r->pool, sizeof(ngx_http_posted_request_t));
    if (f->posted == NULL) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate the posted request of the wait");
    }
  }

  if (ngx_mrb_fiber_hold(&f->base) != NGX_OK) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "failed to keep the fiber of the handler from the GC");
  }

  return f;
}

// What ngx_http_mrb_fiber_log_raise needs: the request, and the handler kind
// to restore before the exception is logged.
typedef struct {
  ngx_http_request_t *r;
  ngx_http_mruby_ctx_t *ctx;
  ngx_http_mruby_handler_kind_t outer_kind;
} ngx_http_mrb_fiber_log_t;

// Logs the exception of a fiber that raised. The kind of the handler that
// was set before the fiber ran comes back first, as when the exception was
// logged after the fiber returned: the inspect of the exception is Ruby code
// that runs outside the handler fiber.
static void ngx_http_mrb_fiber_log_raise(mrb_state *mrb, mrb_value exc, void *data)
{
  ngx_http_mrb_fiber_log_t *log = data;

  log->ctx->handler_kind = log->outer_kind;
  ngx_mrb_raise_error(mrb, exc, log->r);
}

ngx_mrb_fiber_outcome_t ngx_mrb_start_fiber(ngx_http_request_t *r, mrb_state *mrb, struct RProc *rproc,
                                            mrb_value *result, ngx_http_mruby_handler_kind_t kind,
                                            ngx_http_mrb_fiber_t **record)
{
  ngx_http_mrb_fiber_t *f;
  ngx_http_mruby_ctx_t *ctx;

  *record = NULL;
  ctx = ngx_mrb_http_get_module_ctx(mrb, r);
  ctx->async_handler_result = result;

  f = ngx_pcalloc(r->pool, sizeof(ngx_http_mrb_fiber_t));
  if (f == NULL) {
    // the handler ends as after an exception, with 500
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: failed to allocate the fiber", MODULE_NAME,
                  __func__, __LINE__);
    return NGX_MRB_FIBER_RAISED;
  }
  ngx_mrb_fiber_init(&f->base, mrb, NGX_MRB_FIBER_HTTP);
  f->kind = kind;
  f->sleep.r = r;
  *record = f;

  // The RProc of the code is prepared once, when the code is compiled
  // (ngx_http_mruby_prepare_proc). The fiber takes its slot in the GC root
  // holder at its first wait (ngx_http_mrb_fiber_prepare_wait); a handler
  // that never waits takes none and adds no cleanup.
  f->base.fiber = mrb_fiber_new(mrb, rproc);
  if (mrb->exc) {
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "%s NOTICE %s:%d: preparing fiber got the raise, leave the fiber", MODULE_NAME, __func__, __LINE__);
    f->base.state = NGX_MRB_FIBER_FAILED;
    ngx_mrb_raise_error(mrb, mrb_obj_value(mrb->exc), r);
    mrb->exc = NULL;
    return NGX_MRB_FIBER_RAISED;
  }

  return ngx_mrb_run_fiber(mrb, &f->base.fiber, result);
}

static ngx_mrb_fiber_outcome_t ngx_mrb_run_fiber(mrb_state *mrb, mrb_value *fiber_proc, mrb_value *result)
{
  ngx_http_request_t *r = ngx_mrb_get_request();
  mrb_value handler_result = mrb_nil_value();
  ngx_http_mruby_ctx_t *ctx;
  ngx_http_mrb_fiber_t *f = (ngx_http_mrb_fiber_t *)fiber_proc;
  ngx_mrb_fiber_outcome_t outcome;
  ngx_http_mrb_fiber_log_t log;
  ngx_http_mrb_fiber_t *prev;
  mrb_value arg;
  const mrb_value *argp;
  mrb_bool raised = FALSE;

  ctx = ngx_mrb_http_get_module_ctx(mrb, r);
  ctx->fiber_proc = fiber_proc;

  // Nginx::Async reads the kind of the handler whose fiber runs now. The kind
  // that was set before comes back when this fiber ends or yields, so Ruby
  // code that runs for the request outside a handler fiber sees
  // NGX_HTTP_MRUBY_HANDLER_NONE, for example the to_s that ngx_mrb_run calls
  // on the result of mruby_set.
  log.r = r;
  log.ctx = ctx;
  log.outer_kind = ctx->handler_kind;
  ctx->handler_kind = f->kind;
  // The response of the subrequest that the fiber waited for is what its
  // Fiber.yield returns, so Nginx::Async::HTTP.sub_request returns it
  argp = NULL;
  if (f->has_response) {
    f->has_response = 0;
    arg = mrb_protect_error(mrb, ngx_mrb_async_http_response_body, ctx, &raised);
    if (raised) {
      ngx_mrb_raise_error(mrb, arg, r);
      mrb->exc = NULL;
      arg = mrb_nil_value();
    }
    argp = &arg;
  }

  // A wait of this run decides again how it ends (see wake)
  f->wake = 0;
  prev = ngx_http_mrb_running;
  ngx_http_mrb_running = f;
  outcome = ngx_mrb_fiber_resume(&f->base, argp, &handler_result, ngx_http_mrb_fiber_log_raise, &log);
  ngx_http_mrb_running = prev;
  ctx->handler_kind = log.outer_kind;

  if (outcome == NGX_MRB_FIBER_REFUSED) {
    // the record has ended: the handler ends as after an exception, with 500
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: the fiber is not resumed: its handler has ended",
                  MODULE_NAME, __func__, __LINE__);
    return NGX_MRB_FIBER_RAISED;
  }

  if (outcome == NGX_MRB_FIBER_RAISED) {
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "%s NOTICE %s:%d: fiber got the raise, leave the fiber",
                  MODULE_NAME, __func__, __LINE__);
    return outcome;
  }

  if (outcome == NGX_MRB_FIBER_WAITS && !ngx_mrb_handler_can_wait(f->kind)) {
    // Only a direct Fiber.yield gets here, since Nginx::Async raises in this
    // handler. Nothing would resume the fiber, so it holds no slot in the GC
    // root, and the handler ends as a finished one with status 500, which
    // ngx_mrb_finalize_rputs returns as it does after an exception.
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "%s ERROR %s:%d: %s yielded its fiber, but nginx cannot resume it there", MODULE_NAME, __func__,
                  __LINE__, ngx_mrb_handler_kind_name(f->kind));
    ngx_mrb_fiber_release(&f->base);
    f->base.state = NGX_MRB_FIBER_FAILED;
    r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    f->result = NGX_HTTP_INTERNAL_SERVER_ERROR;
    f->has_result = 1;
    return NGX_MRB_FIBER_RETURNED;
  }

  if (outcome == NGX_MRB_FIBER_RETURNED && result != NULL) {
    *result = handler_result;
  }

  return outcome;
}

/*
 * Resumes a fiber from its timer or from the end of its subrequest, and ends
 * its handler there, in place of nginx's phase checker. A fiber that waits in
 * a call of its handler from nginx's phases is resumed by that handler
 * instead (ngx_http_mrb_fiber_call_again); this function resumes the waits
 * that started elsewhere: in a location that Nginx.redirect runs from Ruby
 * code, and after Nginx::Async::HTTP.sub_request (section 8 of
 * docs/proposals/core-stabilization.md moves the subrequest and
 * Nginx.redirect to the call of the handler in later steps).
 */
static ngx_int_t ngx_mrb_post_fiber(ngx_mrb_reentrant_t *re, ngx_http_mruby_ctx_t *ctx)
{
  ngx_int_t rc = NGX_OK;
  ngx_http_request_t *prev_r;
  ngx_http_mruby_handler_kind_t kind;
  ngx_mrb_fiber_outcome_t outcome;
  ngx_http_mrb_fiber_t *f;
  ngx_flag_t has_result;
  ngx_int_t result = NGX_OK;
  int ai;

  ai = mrb_gc_arena_save(re->mrb);

  // re->r is the current request only until this function returns (see ngx_mrb_run())
  prev_r = ngx_mrb_get_request();

  // A record whose owner hook has run (CANCELLED) holds no slot any more,
  // so its fiber is not resumed. The timer of a cancelled record is deleted;
  // this guards the end of a subrequest that nginx reports after the request
  // cleanups of its main request ran.
  if (re->fiber != NULL && ((ngx_mrb_fiber_t *)re->fiber)->state != NGX_MRB_FIBER_CANCELLED) {
    // the handler that runs the fiber, for ngx_mrb_finalize_rputs below; read
    // before re->fiber is cleared
    f = (ngx_http_mrb_fiber_t *)re->fiber;
    kind = f->kind;
    ngx_mrb_push_request(re->r);
    re->r->headers_out.status = re->fiber_prev_status;

    outcome = ngx_mrb_run_fiber(re->mrb, re->fiber, ctx->async_handler_result);
    if (outcome == NGX_MRB_FIBER_WAITS) {
      // can resume the fiber and wait the epoll timer
      mrb_gc_arena_restore(re->mrb, ai);
      ngx_mrb_push_request(prev_r);
      return NGX_DONE;
    }

    // can not resume the fiber, the fiber was finished (it holds no slot in
    // the GC root holder any more)
    re->fiber = NULL;

    if (outcome == NGX_MRB_FIBER_RAISED) {
      // ngx_mrb_fiber_resume has logged the exception and cleared mrb->exc,
      // which all requests share
      rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    } else if (re->sr == NULL && ctx->set_var_target.len > 1) {
      if (ctx->set_var_target.data[0] != '$') {
        ngx_log_error(NGX_LOG_NOTICE, re->r->connection->log, 0,
                      "%s NOTICE %s:%d: invalid variable name error name: %s", MODULE_NAME, __func__, __LINE__,
                      ctx->set_var_target.data);
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
      } else {
        // Delete the leading dollar(ctx->set_var_target.data+1)
        ngx_mrb_var_set_vector(re->mrb, mrb_top_self(re->mrb), (char *)ctx->set_var_target.data + 1,
                               ctx->set_var_target.len - 1, *ctx->async_handler_result, re->r);
      }
    }

    // ngx_mrb_finalize_rputs would replace a 500 set above with the status
    // the handler had set before it failed
    if (rc == NGX_OK) {
      has_result = ngx_http_mrb_fiber_result(f, &result);
      rc = ngx_mrb_finalize_rputs(re->r, ctx, kind, has_result, result);
    }
  } else if (re->fiber != NULL) {
    ngx_log_error(NGX_LOG_NOTICE, re->r->connection->log, 0,
                  "%s NOTICE %s:%d: the fiber is not resumed: its request cleanup has run", MODULE_NAME, __func__,
                  __LINE__);
    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
  } else {
    ngx_log_error(NGX_LOG_NOTICE, re->r->connection->log, 0, "%s NOTICE %s:%d: unexpected error, fiber missing",
                  MODULE_NAME, __func__, __LINE__);
    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  mrb_gc_arena_restore(re->mrb, ai);
  ngx_mrb_push_request(prev_r);

  // NGX_HTTP_OK: a post_read or access handler sent its output; with
  // NGX_DECLINED the request goes on, and a later handler has its own result
  if (rc != NGX_OK && rc != NGX_HTTP_OK && rc != NGX_DECLINED) {
    re->r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  if (rc == NGX_DECLINED) {
    re->r->phase_handler++;
    ngx_http_core_run_phases(re->r);
  }
  return rc;
}

/*
 * The wake (section 4.4 of docs/proposals/core-stabilization.md): the record
 * becomes READY, and the request is posted, so that nginx calls its write
 * event handler, ngx_http_mrb_wait_handler, as for any request that is not
 * the active one of its connection. The entry of the posted request is kept
 * in the record: ngx_http_post_request would allocate one from the pool for
 * each call without it. The timer runs outside ngx_http_request_handler, so
 * it runs the posted requests of the connection itself, as nginx's
 * ngx_http_file_cache_lock_wait_handler does.
 */
static void ngx_http_mrb_fiber_wake(ngx_http_mrb_fiber_t *f)
{
  ngx_http_request_t *r = f->sleep.r;

  if (f->base.state != NGX_MRB_FIBER_WAITING) {
    // not reached: the owner hook deletes the timer of a cancelled record,
    // and a record waits for one timer at a time
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: the timer fired for a fiber that does not wait",
                  MODULE_NAME, __func__, __LINE__);
    return;
  }

  f->base.state = NGX_MRB_FIBER_READY;
  ngx_http_post_request(r, f->posted);
  ngx_http_run_posted_requests(r->connection);
}

/*
 * The fiber of an mruby_set handler is resumed here, not by its handler: the
 * handler runs inside the script of the rewrite module, which starts the
 * script from its first directive each time nginx calls it, so a second call
 * would run the directives before the mruby_set again. When the code
 * returns, its value is assigned to the variable and the phases go on with
 * the next handler, as nginx does when the rewrite module's handler returns
 * NGX_DECLINED; the directives of the same script after the mruby_set ran
 * before the sleep, without the value. A status that the code set with
 * Nginx.return does not end the handler, as without a wait. An exception
 * answers 500: no phase checker is left to end the request, because the
 * rewrite module's handler returned already.
 */
static void ngx_http_mrb_resume_set(ngx_http_request_t *r, ngx_http_mruby_ctx_t *ctx, ngx_http_mrb_fiber_t *f)
{
  mrb_state *mrb = f->base.mrb;
  ngx_http_request_t *prev_r;
  ngx_mrb_fiber_outcome_t outcome;
  mrb_value value = mrb_nil_value();
  ngx_int_t rc = NGX_DECLINED;
  int ai;

  ai = mrb_gc_arena_save(mrb);
  prev_r = ngx_mrb_get_request();
  ngx_mrb_push_request(r);

  ctx->wait = NULL;
  ctx->sub_response_more = 0;
  ctx->async_sleep_pending = 0;
  outcome = ngx_mrb_run_fiber(mrb, &f->base.fiber, &value);

  if (outcome == NGX_MRB_FIBER_WAITS) {
    if (ctx->async_sleep_pending || ctx->sub_response_more) {
      ngx_http_mrb_fiber_wait_on_nginx(r, ctx, f);
    }
    rc = NGX_DONE;
  } else if (outcome == NGX_MRB_FIBER_RAISED) {
    // ngx_mrb_fiber_resume has logged the exception and cleared mrb->exc
    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
  } else if (ctx->set_var_target.len > 1 && ctx->set_var_target.data[0] == '$') {
    // the value of the ended fiber is in no frame any more
    mrb_gc_protect(mrb, value);
    // Delete the leading dollar(ctx->set_var_target.data+1)
    ngx_mrb_var_set_vector(mrb, mrb_top_self(mrb), (char *)ctx->set_var_target.data + 1, ctx->set_var_target.len - 1,
                           value, r);
  } else {
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "%s NOTICE %s:%d: invalid variable name error name: %V",
                  MODULE_NAME, __func__, __LINE__, &ctx->set_var_target);
    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  mrb_gc_arena_restore(mrb, ai);
  ngx_mrb_push_request(prev_r);

  if (rc == NGX_DECLINED) {
    r->phase_handler++;
    r->write_event_handler = ngx_http_core_run_phases;
    ngx_http_core_run_phases(r);
  } else if (rc != NGX_DONE) {
    ngx_http_finalize_request(r, rc);
  }
}

/*
 * The write event handler of a request whose handler waits for nginx to call
 * it again. It ignores events while the record waits, as
 * ngx_http_limit_req_module does while it delays a request, so that nginx
 * does not run the phases, and the handler, again. After the wake it runs the
 * phases from the handler that waits, whose checker calls it again
 * (ngx_http_mrb_fiber_call_again); an mruby_set handler is resumed here.
 */
static void ngx_http_mrb_wait_handler(ngx_http_request_t *r)
{
  ngx_http_mruby_ctx_t *ctx;
  ngx_http_mrb_fiber_t *f;

  ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);
  f = ctx != NULL ? ctx->wait : NULL;

  if (f != NULL && f->base.state == NGX_MRB_FIBER_WAITING) {
    return;
  }

  if (f == NULL || f->base.state != NGX_MRB_FIBER_READY) {
    // An mruby_set handler that called Nginx::Async::HTTP.sub_request after
    // its sleep waits for the subrequest without a record here (its end is
    // the old path of ngx_mrb_post_fiber), and nginx runs this handler when
    // the subrequest ends: the request ends with 500 instead of running the
    // code of the mruby_set again. Step 8 of section 8 of
    // docs/proposals/core-stabilization.md makes sub_request raise there.
    // Otherwise nothing but the handler's call clears the record while this
    // handler is set, and nginx does not call the write event handler of a
    // request that it terminated.
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "%s ERROR %s:%d: the request waits, but no handler of it is ready to resume", MODULE_NAME, __func__,
                  __LINE__);
    if (ctx != NULL) {
      ctx->wait = NULL;
    }
    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    return;
  }

  if (f->kind == NGX_HTTP_MRUBY_HANDLER_SET) {
    ngx_http_mrb_resume_set(r, ctx, f);
    return;
  }

  r->write_event_handler = ngx_http_core_run_phases;
  ngx_http_core_run_phases(r);
}

void ngx_http_mrb_fiber_wait_on_nginx(ngx_http_request_t *r, ngx_http_mruby_ctx_t *ctx, ngx_http_mrb_fiber_t *f)
{
  f->wake = 1;
  ctx->wait = f;
  r->write_event_handler = ngx_http_mrb_wait_handler;

  if (f->kind == NGX_HTTP_MRUBY_HANDLER_CONTENT) {
    // The checker of the content phase finalizes the request with the
    // NGX_DONE that the handler returns, which drops one reference to the
    // request (ngx_http_finalize_connection). Take that reference first, as
    // nginx's own handlers do before they return NGX_DONE, so that the
    // request stays until nginx calls the handler again, after the timer or
    // after the subrequest.
    r->main->count++;
  }
}

ngx_int_t ngx_http_mrb_fiber_call_again(ngx_http_request_t *r, ngx_http_mruby_ctx_t *ctx,
                                        ngx_http_mruby_handler_kind_t kind, mrb_value *result,
                                        ngx_http_mrb_fiber_t **record, ngx_mrb_fiber_outcome_t *outcome)
{
  ngx_http_mrb_fiber_t *f = ctx->wait;

  if (f == NULL || f->kind != kind || f->sleep.r != r) {
    return NGX_DECLINED;
  }

  switch (f->base.state) {
  case NGX_MRB_FIBER_WAITING:
    // nginx ran the phases while the record waits: the handler waits on, and
    // its code does not start again
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s INFO %s:%d: the handler waits; its code is not run again",
                  MODULE_NAME, __func__, __LINE__);
    r->write_event_handler = ngx_http_mrb_wait_handler;
    if (kind == NGX_HTTP_MRUBY_HANDLER_CONTENT) {
      r->main->count++;
    }
    return NGX_DONE;

  case NGX_MRB_FIBER_READY:
    ctx->wait = NULL;
    *record = f;
    *outcome = ngx_mrb_run_fiber(f->base.mrb, &f->base.fiber, result);
    return NGX_OK;

  default:
    ctx->wait = NULL;
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: the handler of the request has ended",
                  MODULE_NAME, __func__, __LINE__);
    return NGX_ERROR;
  }
}

ngx_flag_t ngx_http_mrb_fiber_result(ngx_http_mrb_fiber_t *f, ngx_int_t *result)
{
  if (f == NULL || !f->has_result) {
    return 0;
  }

  *result = f->result;
  return 1;
}

void ngx_http_mrb_fiber_set_result(ngx_http_request_t *r, ngx_int_t result)
{
  ngx_http_mrb_fiber_t *f = ngx_http_mrb_running;

  if (f == NULL || f->sleep.r != r) {
    return;
  }

  f->result = result;
  f->has_result = 1;
}

static void ngx_mrb_timer_handler(ngx_event_t *ev)
{
  ngx_mrb_reentrant_t *re;
  ngx_http_mrb_fiber_t *f;
  ngx_http_mruby_ctx_t *ctx;
  ngx_connection_t *c;
  ngx_int_t rc;

  re = ev->data;
  f = (ngx_http_mrb_fiber_t *)re->fiber;
  ngx_mrb_fiber_timer_fired(&f->base);

  if (f->wake) {
    ngx_http_mrb_fiber_wake(f);
    return;
  }

  // re is allocated from the request pool, which the finalization below can
  // destroy
  c = re->r->connection;
  // The module context is created again when a handler dropped it after it
  // sent output; NULL means that the allocation failed. The fiber is then not
  // resumed: the owner hook frees its slot when the request ends.
  ctx = ngx_mrb_http_get_module_ctx(NULL, re->r);
  if (ctx == NULL) {
    ngx_log_error(NGX_LOG_ERR, c->log, 0, "%s ERROR %s:%d: failed to allocate the module context to resume the fiber",
                  MODULE_NAME, __func__, __LINE__);
    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
  } else {
    rc = ngx_mrb_post_fiber(re, ctx);
  }

  if (rc != NGX_DECLINED && rc != NGX_DONE) {
    ngx_http_finalize_request(re->r, rc);
    // the finalization can post requests: the parent of a finalized
    // subrequest, or, when the response was already sent (for example by the
    // location that Nginx.redirect ran), the request that
    // ngx_http_terminate_request posts to close the connection. This timer
    // runs outside ngx_http_request_handler, so it runs the posted requests
    // itself, as nginx's ngx_http_file_cache_lock_wait_handler does
    ngx_http_run_posted_requests(c);
  }
}

static mrb_value ngx_mrb_async_sleep(mrb_state *mrb, mrb_value self)
{
  mrb_int timer;
  ngx_http_mrb_fiber_t *f;
  ngx_mrb_reentrant_t *re;
  ngx_http_request_t *r;
  ngx_http_mruby_ctx_t *ctx;

  mrb_get_args(mrb, "i", &timer);

  if (timer <= 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "value of the timer must be a positive number");
  }

  r = ngx_mrb_async_request(mrb, "Nginx::Async.sleep");
  ctx = ngx_mrb_http_get_module_ctx(mrb, r);

  // The owner hook and the slot come first, so that a failure there raises
  // with no timer armed.
  f = ngx_http_mrb_fiber_prepare_wait(mrb, r, ctx);

  re = &f->sleep;
  re->mrb = mrb;
  re->fiber_prev_status = r->headers_out.status;
  re->r = r;
  re->sr = NULL;
  re->fiber = &f->base.fiber;

  ngx_mrb_fiber_arm_timer(&f->base, (ngx_msec_t)timer, ngx_mrb_timer_handler, re);

  // tells ngx_mrb_run_request that the fiber yields to this timer (see there)
  ctx->async_sleep_pending = 1;

  return self;
}

static mrb_value build_response_headers_to_hash(mrb_state *mrb, ngx_http_headers_out_t headers_out)
{
  ngx_list_part_t *part;
  ngx_table_elt_t *header;
  ngx_uint_t i;
  mrb_value hash, key, value;
  int ai;

  hash = mrb_hash_new(mrb);
  part = &(headers_out.headers.part);
  header = part->elts;

  ai = mrb_gc_arena_save(mrb);
  for (i = 0; /* void */; i++) {
    if (i >= part->nelts) {
      if (part->next == NULL) {
        mrb_gc_arena_restore(mrb, ai);
        break;
      }
      part = part->next;
      header = part->elts;
      i = 0;
    }
    key = mrb_str_new(mrb, (const char *)header[i].key.data, header[i].key.len);
    value = mrb_str_new(mrb, (const char *)header[i].value.data, header[i].value.len);
    mrb_hash_set(mrb, hash, key, value);
    mrb_gc_arena_restore(mrb, ai);
  }

  return hash;
}

// response for sub_request
/*
 * The post handler of a subrequest. nginx calls it on each finalization of
 * the subrequest that is not NGX_DONE or NGX_DECLINED; the first call copies
 * the status, the headers and the body that the subrequest has in memory
 * then into the module context of the parent, and the later calls change
 * nothing and return rc.
 *
 * For a record that waits for nginx to call its handler again (wake), the
 * record becomes READY and rc is returned unchanged, as
 * ngx_http_auth_request_done does: nginx then wakes the parent, whose write
 * event handler runs its phases (ngx_http_mrb_wait_handler), and the
 * handler resumes the fiber in the parent's own run of the phases, after
 * the subrequest has ended. A record whose owner ended (CANCELLED) is left
 * alone. A fiber that waits inside another mruby call (a location that
 * Nginx.redirect runs from Ruby code) is resumed here, as before
 * (ngx_mrb_post_fiber), until step 7 of section 8 of
 * docs/proposals/core-stabilization.md.
 */
static ngx_int_t ngx_mrb_async_http_sub_request_done(ngx_http_request_t *sr, void *data, ngx_int_t rc)
{
  ngx_mrb_async_http_ctx_t *actx = data;
  ngx_mrb_reentrant_t *re = actx->re;
  ngx_http_mrb_fiber_t *f = actx->record;
  ngx_http_mruby_ctx_t *ctx;
  ngx_buf_t *buffer = NULL;
  ngx_int_t body_len = 0;

  if (actx->done) {
    return rc;
  }
  actx->done = 1;

  if (f->base.state != NGX_MRB_FIBER_WAITING) {
    return rc;
  }

  re->sr = sr;
  re->r = sr->parent;

  // read mruby context of parent request_rec
  ctx = ngx_mrb_http_get_module_ctx(NULL, sr->parent);
  if (ctx == NULL) {
    return NGX_ERROR;
  }

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sr->parent->connection->log, 0, "http_sub_request done s:%ui",
                 sr->parent->headers_out.status);

  ctx->sub_response_more = 0;

  if (sr->upstream) {
    buffer = &sr->upstream->buffer;
  } else if(sr->out){
    buffer = sr->out->buf;
  }

  if(buffer != NULL) {
      if (buffer->pos != buffer->last) {
        body_len = buffer->last - buffer->pos;
      }
      ctx->sub_response_body = ngx_palloc(re->r->pool, body_len);
      if (ctx->sub_response_body == NULL && body_len > 0) {
        // the parent's handler is resumed with an empty body
        ngx_log_error(NGX_LOG_ERR, sr->connection->log, 0,
                      "%s ERROR %s:%d: failed to allocate the body of the subrequest", MODULE_NAME, __func__, __LINE__);
        body_len = 0;
      }
      if (body_len > 0) {
        ngx_memcpy(ctx->sub_response_body, buffer->pos, body_len);
      }
      ctx->sub_response_body_length = body_len;
      ctx->sub_response_status = sr->headers_out.status;
      ctx->sub_response_headers = sr->headers_out;
  }
  f->has_response = 1;

  if (f->wake) {
    f->base.state = NGX_MRB_FIBER_READY;
    return rc;
  }

  rc = ngx_mrb_post_fiber(re, ctx);
  if (rc != NGX_DECLINED && rc != NGX_OK) {
    ngx_http_finalize_request(re->r, rc);
    return NGX_DONE;
  }

  return rc;
}

static mrb_value ngx_mrb_async_http_sub_request(mrb_state *mrb, mrb_value self)
{
  ngx_mrb_reentrant_t *re;
  ngx_http_request_t *r, *sr;
  ngx_http_post_subrequest_t *ps;
  ngx_str_t *uri;
  ngx_mrb_async_http_ctx_t *actx;
  ngx_http_mruby_ctx_t *ctx;
  ngx_http_mrb_fiber_t *f;
  mrb_value path, query_params;
  ngx_str_t *args = NULL;
  int argc;

  argc = mrb_get_args(mrb, "o|S", &path, &query_params);

  r = ngx_mrb_async_request(mrb, "Nginx::Async::HTTP.sub_request");

  ctx = ngx_mrb_http_get_module_ctx(mrb, r);

  if (RSTRING_LEN(path) == 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "http_sub_request path len is 0");
  }

  // Every allocation of the wait is made and checked, and the owner hook and
  // the slot are in place, before the subrequest is posted, so that a failure
  // raises with nothing posted.
  uri = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
  re = ngx_palloc(r->pool, sizeof(ngx_mrb_reentrant_t));
  actx = ngx_palloc(r->pool, sizeof(ngx_mrb_async_http_ctx_t));
  ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
  if (uri == NULL || re == NULL || actx == NULL || ps == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_palloc failed on ngx_mrb_async_http_sub_request");
  }

  uri->len = RSTRING_LEN(path);
  uri->data = (u_char *)ngx_palloc(r->pool, uri->len);
  if (uri->data == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_palloc failed on ngx_mrb_async_http_sub_request");
  }
  ngx_memcpy(uri->data, RSTRING_PTR(path), uri->len);

  if (argc == 2) {
    args = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    if (args == NULL) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_pcalloc failed on ngx_mrb_async_http_sub_request");
    }
    args->len = RSTRING_LEN(query_params);
    if (args->len > 0) {
      args->data = (u_char *)ngx_palloc(r->pool, args->len);
      if (args->data == NULL) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_palloc failed on ngx_mrb_async_http_sub_request");
      }
      ngx_memcpy(args->data, RSTRING_PTR(query_params), args->len);
    }
  }

  f = ngx_http_mrb_fiber_prepare_wait(mrb, r, ctx);

  re->mrb = mrb;
  re->fiber_prev_status = r->headers_out.status;
  re->sr = NULL;
  re->fiber = ctx->fiber_proc;

  actx->uri = uri;
  actx->re = re;
  actx->record = f;
  actx->done = 0;
  f->has_response = 0;

  ps->handler = ngx_mrb_async_http_sub_request_done;
  ps->data = actx;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_sub_request send to %V", actx->uri);

  if (ngx_http_subrequest(r, actx->uri, args, &sr, ps, NGX_HTTP_SUBREQUEST_IN_MEMORY) != NGX_OK) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_http_subrequest failed for http_sub_rquest method");
  }

  ctx->sub_response_more = 1;

  return self;
}

// A new Nginx::Async::HTTP::Response of the response that the module
// context ctx holds
static mrb_value ngx_mrb_async_http_response_new(mrb_state *mrb, ngx_http_mruby_ctx_t *ctx)
{
  struct RClass *response_class, *http_class, *async_class, *ngx_class;
  mrb_value sub_response_instance;

  mrb_value headers = build_response_headers_to_hash(mrb, ctx->sub_response_headers);
  mrb_value status = mrb_fixnum_value(ctx->sub_response_status);
  mrb_value body = mrb_str_new(mrb, (char *)ctx->sub_response_body, ctx->sub_response_body_length);

  ngx_class = mrb_class_get_id(mrb, NGX_HTTP_MRUBY_SYM(mrb, NGINX));
  async_class =
      (struct RClass *)mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(ngx_class), NGX_HTTP_MRUBY_SYM(mrb, ASYNC)));
  http_class =
      (struct RClass *)mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(async_class), NGX_HTTP_MRUBY_SYM(mrb, HTTP)));
  response_class =
      (struct RClass *)mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(http_class), NGX_HTTP_MRUBY_SYM(mrb, RESPONSE)));
  sub_response_instance = mrb_class_new_instance(mrb, 0, 0, response_class);

  mrb_iv_set(mrb, sub_response_instance, NGX_HTTP_MRUBY_SYM(mrb, IV_HEADERS), headers);
  mrb_iv_set(mrb, sub_response_instance, NGX_HTTP_MRUBY_SYM(mrb, IV_STATUS), status);
  mrb_iv_set(mrb, sub_response_instance, NGX_HTTP_MRUBY_SYM(mrb, IV_BODY), body);
  return sub_response_instance;
}

// For mrb_protect_error: ngx_mrb_run_fiber builds the response outside Ruby
// code
static mrb_value ngx_mrb_async_http_response_body(mrb_state *mrb, void *data)
{
  return ngx_mrb_async_http_response_new(mrb, data);
}

static mrb_value ngx_mrb_async_http_last_response(mrb_state *mrb, mrb_value self)
{
  ngx_http_request_t *r;
  ngx_http_mruby_ctx_t *ctx;

  r = ngx_mrb_get_request_or_raise(mrb);
  ctx = ngx_mrb_http_get_module_ctx(mrb, r);

  return ngx_mrb_async_http_response_new(mrb, ctx);
}

void ngx_mrb_async_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_async, *class_async_http;

  class_async = mrb_define_class_under(mrb, class, "Async", mrb->object_class);
  mrb_define_class_method(mrb, class_async, "__sleep", ngx_mrb_async_sleep, MRB_ARGS_REQ(1));

  class_async_http = mrb_define_class_under(mrb, class_async, "HTTP", mrb->object_class);
  mrb_define_class_method(mrb, class_async_http, "__sub_request", ngx_mrb_async_http_sub_request, MRB_ARGS_ARG(1, 1));
  mrb_define_class_method(mrb, class_async_http, "last_response", ngx_mrb_async_http_last_response, MRB_ARGS_NONE());
}
