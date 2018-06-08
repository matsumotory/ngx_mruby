/*
// ngx_http_mruby_async.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_async.h"

#include "ngx_http_mruby_core.h"
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
} ngx_mrb_reentrant_t;

typedef struct {
  ngx_mrb_reentrant_t *re;
  ngx_str_t *uri;
} ngx_mrb_async_http_ctx_t;

static const struct mrb_data_type ngx_mrb_async_http_ctx_type = {
    "ngx_mrb_async_http_ctx_t",
    mrb_free,
};

static void replace_stop(mrb_irep *irep)
{
  // A part of them refer to https://github.com/h2o/h2o
  // Replace OP_STOP with OP_RETURN to avoid stop VM
  irep->iseq[irep->ilen - 1] = MKOP_AB(OP_RETURN, irep->nlocals, OP_R_NORMAL);
}

mrb_value ngx_mrb_start_fiber(ngx_http_request_t *r, mrb_state *mrb, struct RProc *rproc, mrb_value *result)
{
  mrb_value handler_proc;
  mrb_value *fiber_proc;
  ngx_http_mruby_ctx_t *ctx;

  ctx = ngx_mrb_http_get_module_ctx(mrb, r);
  ctx->async_handler_result = result;

  replace_stop(rproc->body.irep);
  handler_proc = mrb_obj_value(mrb_proc_new(mrb, rproc->body.irep));

  if (r->parent)  {
    fiber_proc = (mrb_value *)ngx_palloc(r->parent->pool, sizeof(mrb_value));
  } else {
    fiber_proc = (mrb_value *)ngx_palloc(r->pool, sizeof(mrb_value));
  }

  *fiber_proc = mrb_funcall(mrb, mrb_obj_value(mrb->kernel_module), "_ngx_mrb_prepare_fiber", 1, handler_proc);

  return ngx_mrb_run_fiber(mrb, fiber_proc, result);
}

mrb_value ngx_mrb_run_fiber(mrb_state *mrb, mrb_value *fiber_proc, mrb_value *result)
{
  mrb_value resume_result = mrb_nil_value();
  ngx_http_request_t *r = ngx_mrb_get_request();
  mrb_value aliving = mrb_false_value();
  mrb_value handler_result = mrb_nil_value();

  // Fiber wrapped in proc
  mrb->ud = fiber_proc;

  resume_result = mrb_funcall(mrb, *fiber_proc, "call", 0, NULL);
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

  if (!mrb_test(aliving) && result != NULL) {
    *result = handler_result;
  }

  return aliving;
}

static ngx_int_t ngx_mrb_post_fiber(ngx_mrb_reentrant_t *re, ngx_http_mruby_ctx_t *ctx)
{
  ngx_int_t rc = NGX_OK;
  int ai;

  ai = mrb_gc_arena_save(re->mrb);

  if (re->fiber != NULL) {
    ngx_mrb_push_request(re->r);

    if (mrb_test(ngx_mrb_run_fiber(re->mrb, re->fiber, ctx->async_handler_result))) {
      // can resume the fiber and wait the epoll timer
      mrb_gc_arena_restore(re->mrb, ai);
      return NGX_DONE;
    } else {
      // can not resume the fiber, the fiber was finished
      mrb_gc_unregister(re->mrb, *re->fiber);
      re->fiber = NULL;
    }

    ngx_http_run_posted_requests(re->r->connection);

    if (re->mrb->exc) {
      ngx_mrb_raise_error(re->mrb, mrb_obj_value(re->mrb->exc), re->r);
      rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    } else if (ctx->set_var_target.len > 1) {
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

    rc = ngx_mrb_finalize_rputs(re->r, ctx);
  } else {
    ngx_log_error(NGX_LOG_NOTICE, re->r->connection->log, 0, "%s NOTICE %s:%d: unexpected error, fiber missing",
                  MODULE_NAME, __func__, __LINE__);
    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  mrb_gc_arena_restore(re->mrb, ai);

  if (rc != NGX_OK) {
    re->r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  if (rc == NGX_DECLINED) {
    re->r->phase_handler++;
    ngx_http_core_run_phases(re->r);
  }
  return rc;
}

static void ngx_mrb_timer_handler(ngx_event_t *ev)
{
  ngx_mrb_reentrant_t *re;
  ngx_http_mruby_ctx_t *ctx;
  ngx_int_t rc = NGX_OK;

  re = ev->data;
  ctx = ngx_mrb_http_get_module_ctx(NULL, re->r);

  if (ctx == NULL) {
    rc = NGX_ERROR;
  }
  rc = ngx_mrb_post_fiber(re, ctx);

  if (rc != NGX_DECLINED && rc != NGX_DONE) {
    ngx_http_finalize_request(re->r, rc);
  }
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
  mrb_int timer;
  u_char *p;
  ngx_event_t *ev;
  ngx_mrb_reentrant_t *re;
  ngx_http_cleanup_t *cln;
  ngx_http_request_t *r;

  mrb_get_args(mrb, "i", &timer);

  if (timer <= 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "value of the timer must be a positive number");
  }

  r = ngx_mrb_get_request();
  p = ngx_palloc(r->pool, sizeof(ngx_event_t) + sizeof(ngx_mrb_reentrant_t));
  re = (ngx_mrb_reentrant_t *)(p + sizeof(ngx_event_t));
  re->mrb = mrb;
  re->fiber = (mrb_value *)mrb->ud;
  re->r = r;

  // keeps the object from GC when can resume the fiber
  // Don't forget to remove the object using
  // mrb_gc_unregister, otherwise your object will leak
  mrb_gc_register(mrb, *re->fiber);

  ev = (ngx_event_t *)p;
  ngx_memzero(ev, sizeof(ngx_event_t));
  ev->handler = ngx_mrb_timer_handler;
  ev->data = re;
  ev->log = ngx_cycle->log;

  ngx_add_timer(ev, (ngx_msec_t)timer);

  cln = ngx_http_cleanup_add(r, 0);
  if (cln == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_http_cleanup_add failed");
  }

  cln->handler = ngx_mrb_async_sleep_cleanup;
  cln->data = ev;

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
static ngx_int_t ngx_mrb_async_http_sub_request_done(ngx_http_request_t *sr, void *data, ngx_int_t rc)
{
  ngx_mrb_async_http_ctx_t *actx = data;
  ngx_mrb_reentrant_t *re = actx->re;
  ngx_http_mruby_ctx_t *ctx;

  re->r = sr->parent;
  // read mruby context of parent request_rec
  ctx = ngx_mrb_http_get_module_ctx(NULL, sr->parent);
  if (ctx == NULL) {
    return NGX_ERROR;
  }

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sr->parent->connection->log, 0, "http_sub_request done s:%ui",
                 sr->parent->headers_out.status);
  ctx->sub_response_more = 0;

  return ngx_mrb_post_fiber(re, ctx);
}

static mrb_value ngx_mrb_async_http_sub_request(mrb_state *mrb, mrb_value self)
{
  ngx_mrb_reentrant_t *re;
  ngx_http_request_t *r, *sr;
  ngx_http_post_subrequest_t *ps;
  ngx_str_t *uri;
  ngx_mrb_async_http_ctx_t *actx;
  ngx_http_mruby_ctx_t *ctx;
  mrb_value path, query_params;
  ngx_str_t *args = NULL;
  int argc;

  argc = mrb_get_args(mrb, "o|H", &path, &query_params);

  r = ngx_mrb_get_request();
  uri = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
  if (uri == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_pcalloc failed on ngx_mrb_async_http_sub_request");
  }

  uri->len = RSTRING_LEN(path);
  if (uri->len == 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "http_sub_request path len is 0");
  }

  uri->data = (u_char *)ngx_palloc(r->pool, RSTRING_LEN(path));
  ngx_memcpy(uri->data, RSTRING_PTR(path), uri->len);

  if (argc == 2) {
    struct RClass *http_class;
    struct RClass *ngx_class = mrb_class_get(mrb, "Nginx");
    mrb_value http_instance;

    args = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    http_class = (struct RClass *)mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(ngx_class), mrb_intern_cstr(mrb, "HttpUtils")));

    http_instance = mrb_class_new_instance(mrb, 0, 0, http_class);
    query_params = mrb_funcall(mrb, http_instance, "encode_parameters", 1, query_params);

    args->len = RSTRING_LEN(query_params);
    args->data = (u_char *)ngx_palloc(r->pool, RSTRING_LEN(query_params));
    ngx_memcpy(args->data, RSTRING_PTR(query_params), args->len);
  }

  re = (ngx_mrb_reentrant_t *)ngx_palloc(r->pool, sizeof(ngx_mrb_reentrant_t));
  re->mrb = mrb;
  re->fiber = (mrb_value *)mrb->ud;

  mrb_gc_register(mrb, *re->fiber);

  actx = (ngx_mrb_async_http_ctx_t *)ngx_palloc(r->pool, sizeof(ngx_mrb_async_http_ctx_t));
  actx->uri = uri;
  actx->re = re;

  ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
  if (ps == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_palloc failed for http_sub_request post subrequest");
  }

  ps->handler = ngx_mrb_async_http_sub_request_done;
  ps->data = actx;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_sub_request send to %V", actx->uri);

  if (ngx_http_subrequest(r, actx->uri, args, &sr, ps, NGX_HTTP_SUBREQUEST_IN_MEMORY) != NGX_OK) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_http_subrequest failed for http_sub_rquest method");
  }

  ctx = ngx_mrb_http_get_module_ctx(mrb, r);
  ctx->sub_response_more = 1;

  return self;
}

static mrb_value ngx_mrb_async_http_last_response(mrb_state *mrb, mrb_value self)
{
  struct RClass *response_class, *http_class, *async_class, *ngx_class;
  ngx_http_request_t *r;
  ngx_http_mruby_ctx_t *ctx;
  mrb_value sub_response_instance;

  r = ngx_mrb_get_request();
  ctx = ngx_mrb_http_get_module_ctx(mrb, r);

  mrb_value headers = build_response_headers_to_hash(mrb, ctx->sub_response_headers);
  mrb_value status = mrb_fixnum_value(ctx->sub_response_status);
  mrb_value body = mrb_str_new(mrb, (char *)ctx->sub_response_body, ctx->sub_response_body_length);

  ngx_class = mrb_class_get(mrb, "Nginx");
  async_class =
      (struct RClass *)mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(ngx_class), mrb_intern_cstr(mrb, "Async")));
  http_class =
      (struct RClass *)mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(async_class), mrb_intern_cstr(mrb, "HTTP")));
  response_class =
      (struct RClass *)mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(http_class), mrb_intern_cstr(mrb, "Response")));
  sub_response_instance = mrb_class_new_instance(mrb, 0, 0, response_class);

  mrb_iv_set(mrb, sub_response_instance, mrb_intern_cstr(mrb, "@headers"), headers);
  mrb_iv_set(mrb, sub_response_instance, mrb_intern_cstr(mrb, "@status"), status);
  mrb_iv_set(mrb, sub_response_instance, mrb_intern_cstr(mrb, "@body"), body);
  return sub_response_instance;
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
