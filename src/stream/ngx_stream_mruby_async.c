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

typedef struct {
  mrb_state *mrb;
  mrb_value *fiber;
  ngx_stream_session_t *s;
} ngx_stream_mrb_reentrant_t;

static mrb_value ngx_stream_mrb_run_fiber(mrb_state *mrb, mrb_value *fiber_proc, mrb_value *result)
{
  mrb_value resume_result = mrb_nil_value();
  mrb_value aliving = mrb_false_value();
  mrb_value handler_result = mrb_nil_value();
  ngx_stream_mruby_ctx_t *ctx;

  ngx_stream_session_t *s = ngx_mrb_get_session();
  ctx = ngx_stream_mrb_get_module_ctx(mrb, s);
  ctx->fiber_proc = fiber_proc;

  resume_result = mrb_funcall(mrb, *fiber_proc, "call", 0, NULL);
  if (mrb->exc) {
    ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0, "%s NOTICE %s:%d: fiber got the raise, leave the fiber",
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

{
}
