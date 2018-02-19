/*
// ngx_http_mruby_async.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_async.h"
#include "ngx_http_mruby_core.h"
#include "ngx_http_mruby_request.h"

#include <nginx.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <mruby/array.h>
#include <mruby/opcode.h>
#include <mruby/proc.h>
#include <mruby/error.h>

typedef struct {
  mrb_state *mrb;
  mrb_value *fiber;
  ngx_http_request_t *r;
} ngx_mrb_reentrant_t;

static void replace_stop(mrb_irep *irep)
{
  // A part of them refer to https://github.com/h2o/h2o
  // Replace OP_STOP with OP_RETURN to avoid stop VM
  irep->iseq[irep->ilen - 1] = MKOP_AB(OP_RETURN, irep->nlocals, OP_R_NORMAL);
}

void ngx_mrb_run_without_stop(mrb_state *mrb, struct RProc *rproc, mrb_value *result)
{
  mrb_value mrb_result;
  mrb_value proc;

  proc = mrb_obj_value(mrb_proc_new(mrb, rproc->body.irep));

  mrb_result = mrb_funcall(mrb, proc, "call", 0, NULL);
  if (result != NULL) {
    *result = mrb_result;
  }
}

mrb_value ngx_mrb_start_fiber(ngx_http_request_t *r, mrb_state *mrb, struct RProc *rproc, mrb_value *result)
{
  mrb_value handler_proc;
  mrb_value *fiber_proc;

  replace_stop(rproc->body.irep);
  handler_proc = mrb_obj_value(mrb_proc_new(mrb, rproc->body.irep));
  fiber_proc = (mrb_value *)ngx_palloc(r->pool, sizeof(mrb_value));
  *fiber_proc = mrb_funcall(mrb, mrb_obj_value(mrb->kernel_module), "_ngx_mrb_prepare_fiber", 1, handler_proc);

  return ngx_mrb_run_fiber(mrb, fiber_proc, result);
}

mrb_value ngx_mrb_run_fiber(mrb_state *mrb, mrb_value *fiber, mrb_value *result)
{
  mrb_value resume_result = mrb_nil_value();
  ngx_http_request_t *r = ngx_mrb_get_request();
  mrb_value aliving = mrb_false_value();
  mrb_value handler_result = mrb_nil_value();

  mrb->ud = fiber;

  resume_result = mrb_funcall(mrb, *fiber, "call", 0, NULL);
  if (mrb->exc) {
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "%s NOTICE %s:%d: fiber got the raise, leave the fiber",
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
  // result called timer_handler is NULL
  if (result) {
    *result = handler_result;
  }

  // leaves the object in the arena
  mrb_gc_protect(mrb, *fiber);

  return aliving;
}

#define ngx_mrb_resume_fiber(mrb, fiber, result) ngx_mrb_run_fiber(mrb, fiber, result)

static void ngx_mrb_timer_handler(ngx_event_t *ev)
{
  ngx_mrb_reentrant_t *re;
  ngx_http_mruby_ctx_t *ctx;
  ngx_int_t rc = NGX_OK;

  re = ev->data;

  if (re->fiber != NULL) {
    ngx_mrb_push_request(re->r);
    if (!mrb_test(ngx_mrb_resume_fiber(re->mrb, re->fiber, NULL))) {
      re->fiber = NULL;
    }
    if (re->mrb->exc) {
      ngx_mrb_raise_error(re->mrb, mrb_obj_value(re->mrb->exc), re->r);
      rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
  } else {
    ngx_log_error(NGX_LOG_NOTICE, re->r->connection->log, 0,
                  "%s NOTICE %s:%d: unexpected error, fiber missing" MODULE_NAME, __func__, __LINE__);
    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  ctx = ngx_http_get_module_ctx(re->r, ngx_http_mruby_module);
  if (ctx != NULL) {
    if (rc != NGX_OK) {
      re->r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    rc = ngx_mrb_finalize_rputs(re->r, ctx);
  } else {
    rc = NGX_ERROR;
  }

  ngx_http_finalize_request(re->r, rc);
}

static void ngx_mrb_async_sleep_cleanup(void *data)
{
  ngx_event_t *ev = (ngx_event_t *)data;

  if (ev->timer_set) {
    ngx_del_timer(ev);
    return;
  }
}

static mrb_value ngx_mrb_async_sleep(mrb_state *mrb, mrb_value self)
{
  unsigned int timer;
  u_char *p;
  ngx_event_t *ev;
  ngx_mrb_reentrant_t *re;
  ngx_http_cleanup_t *cln;
  ngx_http_request_t *r = ngx_mrb_get_request();

  mrb_get_args(mrb, "i", &timer);

  // suspend the Ruby handler on Nginx::Async.sleep
  // resume the Ruby handler on ngx_mrb_resume_fiber() on ngx_mrb_timer_handler()
  mrb_fiber_yield(mrb, 0, NULL);

  p = ngx_palloc(r->pool, sizeof(ngx_event_t) + sizeof(ngx_mrb_reentrant_t));
  re = (ngx_mrb_reentrant_t *)(p + sizeof(ngx_event_t));
  re->mrb = mrb;
  re->fiber = (mrb_value *)mrb->ud;
  re->r = r;

  ev = (ngx_event_t *)p;
  ngx_memzero(ev, sizeof(ngx_event_t));
  ev->handler = ngx_mrb_timer_handler;
  ev->data = re;
  ev->log = ngx_cycle->log;

  ngx_add_timer(ev, (ngx_msec_t)timer);

  ngx_http_run_posted_requests(r->connection);

  cln = ngx_http_cleanup_add(r, 0);
  if (cln == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_http_cleanup_add failed");
  }

  cln->handler = ngx_mrb_async_sleep_cleanup;
  cln->data = ev;

  return self;
}

void ngx_mrb_async_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_async;

  class_async = mrb_define_class_under(mrb, class, "Async", mrb->object_class);
  mrb_define_class_method(mrb, class_async, "sleep", ngx_mrb_async_sleep, MRB_ARGS_REQ(1));
}
