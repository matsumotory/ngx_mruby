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
#include <mruby/data.h>
#include <mruby/string.h>

#define ngx_mrb_resume_fiber(mrb, fiber) ngx_mrb_run_fiber(mrb, fiber, NULL)

typedef struct {
  mrb_state *mrb;
  mrb_value *fiber;
  ngx_http_request_t *r;
  ngx_http_request_t *sr;
} ngx_mrb_reentrant_t;

typedef struct {
  ngx_mrb_reentrant_t *re;
  ngx_str_t *uri;
} ngx_mrb_async_http_ctx_t;

static const struct mrb_data_type ngx_mrb_async_http_ctx_type = {
    "ngx_mrb_async_http_ctx_t", mrb_free,
};

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
  // result called async mruby handler is NULL via ngx_mrb_resume_fiber
  if (result) {
    *result = handler_result;
  }

  return aliving;
}

static void ngx_mrb_timer_handler(ngx_event_t *ev)
{
  ngx_mrb_reentrant_t *re;
  ngx_http_mruby_ctx_t *ctx;
  ngx_int_t rc = NGX_OK;

  re = ev->data;

  if (re->fiber != NULL) {
    ngx_mrb_push_request(re->r);

    if (mrb_test(ngx_mrb_resume_fiber(re->mrb, re->fiber))) {
      // can resume the fiber and wait the epoll timer
      return;
    } else {
      // can not resume the fiber, the fiber was finished
      mrb_gc_unregister(re->mrb, *re->fiber);
      re->fiber = NULL;
    }

    ngx_http_run_posted_requests(re->r->connection);

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
  ngx_http_request_t *r;

  mrb_get_args(mrb, "i", &timer);

  // suspend the Ruby handler on Nginx::Async.sleep
  // resume the Ruby handler on ngx_mrb_resume_fiber() on ngx_mrb_timer_handler()
  mrb_fiber_yield(mrb, 0, NULL);

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

static mrb_value ngx_mrb_async_http_init(mrb_state *mrb, mrb_value self)
{
  ngx_str_t *uri;
  ngx_mrb_async_http_ctx_t *actx;
  ngx_http_request_t *r = ngx_mrb_get_request();
  mrb_value arg;

  uri = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
  if (uri == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_pcalloc failed on ngx_mrb_async_http_init");
  }

  mrb_get_args(mrb, "o", &arg);
  uri->len = RSTRING_LEN(arg);
  if (uri->len == 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "http_sub_request args len is 0");
  }

  uri->data = (u_char *)ngx_palloc(r->pool, RSTRING_LEN(arg));
  ngx_memcpy(uri->data, RSTRING_PTR(arg), uri->len);

  actx = (ngx_mrb_async_http_ctx_t *)DATA_PTR(self);
  if (actx) {
    mrb_free(mrb, actx);
  }
  DATA_TYPE(self) = &ngx_mrb_async_http_ctx_type;
  DATA_PTR(self) = NULL;

  actx = (ngx_mrb_async_http_ctx_t *)mrb_malloc(mrb, sizeof(ngx_mrb_async_http_ctx_t));
  actx->uri = uri;
  actx->re = NULL;

  DATA_PTR(self) = actx;

  return self;
}

static ngx_int_t ngx_http_mruby_read_sub_response(ngx_http_request_t *sr, ngx_http_mruby_ctx_t *ctx)
{
  u_char *p;
  size_t size, rest;
  ngx_buf_t *b;
  ngx_chain_t *cl, *out;

  ctx->sub_response_status = sr->headers_out.status;
  ctx->sub_response_headers = sr->headers_out;

  if (ctx->body == NULL && sr->headers_out.content_length_n > 0) {
    ctx->sub_response_body = ngx_pcalloc(sr->pool, ctx->sub_response_body_length);
    if (ctx->sub_response_body == NULL) {
      ngx_log_error(NGX_LOG_ERR, sr->connection->log, 0, "%s ERROR %s:%d: ngx_pcalloc failed", MODULE_NAME, __func__,
                    __LINE__);
      return NGX_ERROR;
    }
    ctx->sub_response_last = ctx->sub_response_body;
  }

  p = ctx->sub_response_last;
  out = sr->out;

  for (cl = out; cl != NULL; cl = cl->next) {
    b = cl->buf;
    size = b->last - b->pos;
    rest = ctx->sub_response_body + ctx->sub_response_body_length - p;
    ngx_log_error(NGX_LOG_DEBUG, sr->connection->log, 0, "%s DEBUG %s:%d: filter buf: %uz rest: %uz", MODULE_NAME,
                  __func__, __LINE__, size, rest);
    size = (rest < size) ? rest : size;
    p = ngx_cpymem(p, b->pos, size);
    b->pos += size;
    if (b->last_buf) {
      ctx->sub_response_last = p;
      ngx_log_error(NGX_LOG_DEBUG, sr->connection->log, 0, "%s DEBUG %s:%d: reached last buffer", MODULE_NAME, __func__,
                    __LINE__);
    }
  }

  return NGX_OK;
}

// response for sub_request
static ngx_int_t ngx_mrb_async_http_sub_request_done(ngx_http_request_t *sr, void *data, ngx_int_t rc)
{
  ngx_mrb_async_http_ctx_t *actx = data;
  ngx_mrb_reentrant_t *re = actx->re;
  ngx_http_request_t *r = re->r;
  ngx_http_mruby_ctx_t *ctx;

  // read mruby context of parent request_rec
  ctx = ngx_http_get_module_ctx(re->r, ngx_http_mruby_module);

  if (ctx && ctx->sub_response_done) {
    return NGX_OK;
  }

  if (ctx == NULL) {
    return rc;
  }

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_sub_request done s:%ui", r->headers_out.status);
  ctx->sub_response_done = 1;
  ctx->sub_response_more = 0;

  // copy response data of sub_request to main response ctx
  if (ngx_http_mruby_read_sub_response(sr, ctx) != NGX_OK) {
    return NGX_ERROR;
  }

  if (re->fiber != NULL) {
    ngx_mrb_push_request(re->r);

    if (mrb_test(ngx_mrb_resume_fiber(re->mrb, re->fiber))) {
      // can resume the fiber and wait the epoll
      return rc;
    } else {
      // can not resume the fiber, the fiber was finished
      mrb_gc_unregister(re->mrb, *re->fiber);
      re->fiber = NULL;
    }

    if (re->mrb->exc) {
      ngx_mrb_raise_error(re->mrb, mrb_obj_value(re->mrb->exc), r);
      rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
      ngx_http_finalize_request(r, rc);
    }
  } else {
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "%s NOTICE %s:%d: unexpected error, fiber missing" MODULE_NAME,
                  __func__, __LINE__);
    rc = NGX_ERROR;
    ngx_http_finalize_request(r, rc);
  }

  return rc;
}

static mrb_value ngx_mrb_async_http_sub_request(mrb_state *mrb, mrb_value self)
{
  u_char *p;
  ngx_mrb_reentrant_t *re;
  ngx_http_request_t *r, *sr;
  ngx_http_post_subrequest_t *ps;
  ngx_http_mruby_ctx_t *ctx;
  ngx_mrb_async_http_ctx_t *actx = DATA_PTR(self);

  mrb_fiber_yield(mrb, 0, NULL);

  r = ngx_mrb_get_request();
  p = ngx_palloc(r->pool, sizeof(ngx_event_t) + sizeof(ngx_mrb_reentrant_t));
  re = (ngx_mrb_reentrant_t *)(p + sizeof(ngx_event_t));
  re->mrb = mrb;
  re->fiber = (mrb_value *)mrb->ud;
  re->r = r;

  mrb_gc_register(mrb, *re->fiber);

  ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
  if (ps == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_palloc failed for http_sub_request post subrequest");
  }

  actx->re = re;
  ps->handler = ngx_mrb_async_http_sub_request_done;
  ps->data = actx;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_sub_request send to %V", actx->uri);
  // if (ngx_http_subrequest(r, &actx->uri, NULL, &sr, ps, NGX_HTTP_SUBREQUEST_WAITED) != NGX_OK) {
  if (ngx_http_subrequest(r, actx->uri, NULL, &sr, ps, NGX_HTTP_SUBREQUEST_IN_MEMORY | NGX_HTTP_SUBREQUEST_WAITED) !=
      NGX_OK) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_http_subrequest failed for http_sub_rquest method");
  }

  sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
  if (sr->request_body == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_palloc failed for sr->request_body");
  }

  re->sr = sr;

  // NGX_AGAIN;
  ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);
  if (ctx == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_http_get_module_ctx failed on subrequest method");
  }
  ctx->sub_response_done = 0;
  ctx->sub_response_more = 1;

  return self;
}

static mrb_value build_response_headers_to_hash(mrb_state *mrb, ngx_http_headers_out_t headers_out)
{
  ngx_list_part_t *part;
  ngx_table_elt_t *header;
  ngx_uint_t i;
  mrb_value hash, key, value;

  hash = mrb_hash_new(mrb);
  part = &(headers_out.headers.part);
  header = part->elts;

  for (i = 0; /* void */; i++) {
    if (i >= part->nelts) {
      if (part->next == NULL) {
        break;
      }
      part = part->next;
      header = part->elts;
      i = 0;
    }
    key = mrb_str_new(mrb, (const char *)header[i].key.data, header[i].key.len);
    value = mrb_str_new(mrb, (const char *)header[i].value.data, header[i].value.len);
    mrb_hash_set(mrb, hash, key, value);
  }

  return hash;
}

static mrb_value build_response_to_obj(mrb_state *mrb, ngx_http_mruby_ctx_t *ctx)
{
  mrb_value headers = build_response_headers_to_hash(mrb, ctx->sub_response_headers);
  mrb_value status = mrb_fixnum_value(ctx->sub_response_status);
  mrb_value body = mrb_str_new(mrb, (char *)ctx->sub_response_body, ctx->sub_response_body_length);
  mrb_value response = mrb_hash_new(mrb);

  mrb_hash_set(mrb, response, mrb_symbol_value(mrb_intern_cstr(mrb, "headers")), headers);
  mrb_hash_set(mrb, response, mrb_symbol_value(mrb_intern_cstr(mrb, "status")), status);
  mrb_hash_set(mrb, response, mrb_symbol_value(mrb_intern_cstr(mrb, "body")), body);

  return response;
}

static mrb_value ngx_mrb_async_http_fetch_response(mrb_state *mrb, mrb_value self)
{
  ngx_http_mruby_ctx_t *ctx;
  ngx_mrb_async_http_ctx_t *actx;
  mrb_value response;

  actx = DATA_PTR(self);

  if (!actx) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "Nginx::Async::HTTP instance was missing");
  }

  ctx = ngx_http_get_module_ctx(actx->re->sr, ngx_http_mruby_module);

  if (ctx == NULL) {
    return mrb_nil_value();
  }

  // build response for mruby
  // return the following object:
  // { headers: { "header1" => "hoge", "header2" => "fuga" }, status: 200, body: "hello body world"}
  response = build_response_to_obj(mrb, ctx);

  return response;
}

void ngx_mrb_async_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_async, *class_async_http;

  class_async = mrb_define_class_under(mrb, class, "Async", mrb->object_class);
  mrb_define_class_method(mrb, class_async, "sleep", ngx_mrb_async_sleep, MRB_ARGS_REQ(1));

  class_async_http = mrb_define_class_under(mrb, class_async, "HTTP", mrb->object_class);
  mrb_define_method(mrb, class_async_http, "initialize", ngx_mrb_async_http_init, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_async_http, "http_sub_request", ngx_mrb_async_http_sub_request, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_async_http, "fetch_response", ngx_mrb_async_http_fetch_response, MRB_ARGS_NONE());
}
