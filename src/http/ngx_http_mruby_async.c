/*
// ngx_http_mruby_async.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_async.h"

#include "ngx_http_mruby_core.h"
#include "ngx_http_mruby_debug.h" // with NGX_MRUBY_DEBUG_STATS, counts the mrb_gc_register() calls
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
#include <mruby/internal.h>

typedef struct {
  mrb_state *mrb;
  mrb_value *fiber;
  ngx_http_request_t *r;
  ngx_uint_t fiber_prev_status;
  ngx_http_request_t *sr;
} ngx_mrb_reentrant_t;

typedef struct {
  ngx_mrb_reentrant_t *re;
  ngx_str_t *uri;
} ngx_mrb_async_http_ctx_t;

#ifdef NGX_MRUBY_DEBUG_STATS
/*
// Timers added by Nginx::Async.sleep that have neither fired nor been
// deleted. Signed, so that a timer counted down twice shows as negative.
*/
static ngx_int_t ngx_mrb_async_debug_timers_count = 0;

ngx_int_t ngx_mrb_async_debug_timers(void)
{
  return ngx_mrb_async_debug_timers_count;
}
#endif

/*
 * The fiber of a handler, allocated from the request pool. It is registered
 * with mrb_gc_register once, when it is created, and unregistered once: when
 * it ends, normally or with an exception, or when the request pool is
 * destroyed while the fiber is still suspended. ctx->fiber_proc and re->fiber
 * point to the first member. kind is the handler that runs the fiber, also
 * when a timer or a subrequest resumes it.
 */
typedef struct {
  mrb_value fiber;
  mrb_state *mrb;
  ngx_flag_t registered;
  ngx_http_mruby_handler_kind_t kind;
} ngx_mrb_fiber_t;

// Whether Nginx::Async may suspend the fiber of this kind of handler. nginx
// resumes it for mruby_set and the post_read, server_rewrite, rewrite and
// access handlers; CONTENT stays allowed only so that the behavior of the
// content handler does not change (see ngx_http_mruby_handler_kind_t).
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
 * Returns the current request, or raises a RuntimeError when the handler that
 * runs now cannot wait. Nginx::Async.sleep and Nginx::Async::HTTP.sub_request
 * call it before they arm a timer or post a subrequest, so a refused call
 * leaves nothing behind that could touch the request later.
 */
static ngx_http_request_t *ngx_mrb_async_request(mrb_state *mrb, const char *method)
{
  ngx_http_request_t *r;
  ngx_http_mruby_ctx_t *ctx;

  r = ngx_mrb_get_request();
  ctx = ngx_mrb_http_get_module_ctx(mrb, r);
  if (!ngx_mrb_handler_can_wait(ctx->handler_kind)) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "%s is not available in %s", method, ngx_mrb_handler_kind_name(ctx->handler_kind));
  }

  return r;
}

static void ngx_mrb_fiber_unregister(mrb_value *fiber_proc)
{
  ngx_mrb_fiber_t *f = (ngx_mrb_fiber_t *)fiber_proc;

  if (f->registered) {
    f->registered = 0;
    mrb_gc_unregister(f->mrb, f->fiber);
  }
}

static void ngx_mrb_fiber_cleanup(void *data)
{
  ngx_mrb_fiber_unregister(data);
}

mrb_value ngx_mrb_start_fiber(ngx_http_request_t *r, mrb_state *mrb, struct RProc *rproc, mrb_value *result,
                              ngx_http_mruby_handler_kind_t kind)
{
  struct RProc *handler_proc;
  mrb_value *fiber_proc;
  ngx_mrb_fiber_t *f;
  ngx_pool_cleanup_t *cln;
  ngx_http_mruby_ctx_t *ctx;

  ctx = ngx_mrb_http_get_module_ctx(mrb, r);
  ctx->async_handler_result = result;

  handler_proc = rproc;
  handler_proc->upper = NULL;
  handler_proc->e.target_class = mrb->object_class;

  f = ngx_pcalloc(r->pool, sizeof(ngx_mrb_fiber_t));
  cln = ngx_pool_cleanup_add(r->pool, 0);
  if (f == NULL || cln == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: failed to allocate the fiber", MODULE_NAME,
                  __func__, __LINE__);
    // ngx_mrb_run reads a fiber that is not alive and has no exception as a
    // finished handler; with this status ngx_mrb_finalize_rputs returns 500,
    // as it does after an exception
    r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    return mrb_false_value();
  }
  f->mrb = mrb;
  f->kind = kind;
  fiber_proc = &f->fiber;

  *fiber_proc = mrb_fiber_new(mrb, rproc);
  if (mrb->exc) {
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "%s NOTICE %s:%d: preparing fiber got the raise, leave the fiber", MODULE_NAME, __func__, __LINE__);
    return mrb_false_value();
  }

  // keeps the fiber from GC while it can be resumed; ngx_mrb_fiber_unregister
  // removes it when the fiber ends, and the pool cleanup when the request
  // ends first
  mrb_gc_register(mrb, *fiber_proc);
  f->registered = 1;
  cln->handler = ngx_mrb_fiber_cleanup;
  cln->data = f;

  return ngx_mrb_run_fiber(mrb, fiber_proc, result);
}

mrb_value ngx_mrb_run_fiber(mrb_state *mrb, mrb_value *fiber_proc, mrb_value *result)
{
  ngx_http_request_t *r = ngx_mrb_get_request();
  mrb_value aliving = mrb_false_value();
  mrb_value handler_result = mrb_nil_value();
  ngx_http_mruby_ctx_t *ctx;
  ngx_mrb_fiber_t *f = (ngx_mrb_fiber_t *)fiber_proc;
  ngx_http_mruby_handler_kind_t outer_kind;

  ctx = ngx_mrb_http_get_module_ctx(mrb, r);
  ctx->fiber_proc = fiber_proc;

  // Nginx::Async reads the kind of the handler whose fiber runs now. The kind
  // that was set before comes back when this fiber ends or yields, so Ruby
  // code that runs for the request outside a handler fiber sees
  // NGX_HTTP_MRUBY_HANDLER_NONE, for example the to_s that ngx_mrb_run calls
  // on the result of mruby_set.
  outer_kind = ctx->handler_kind;
  ctx->handler_kind = f->kind;
  handler_result = mrb_fiber_resume(mrb, *fiber_proc, 0, NULL);
  ctx->handler_kind = outer_kind;

  if (mrb->exc) {
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "%s NOTICE %s:%d: fiber got the raise, leave the fiber",
                  MODULE_NAME, __func__, __LINE__);
    ngx_mrb_fiber_unregister(fiber_proc);
    return mrb_false_value();
  }

  aliving = mrb_fiber_alive_p(mrb, *fiber_proc);

  if (mrb_test(aliving) && !ngx_mrb_handler_can_wait(f->kind)) {
    // Only a direct Fiber.yield gets here, since Nginx::Async raises in this
    // handler. Nothing would resume the fiber, so it is dropped from the GC
    // root, and the handler ends as a finished one with status 500, which
    // ngx_mrb_finalize_rputs returns as it does after an exception.
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "%s ERROR %s:%d: %s yielded its fiber, but nginx cannot resume it there", MODULE_NAME, __func__,
                  __LINE__, ngx_mrb_handler_kind_name(f->kind));
    ngx_mrb_fiber_unregister(fiber_proc);
    r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    return mrb_false_value();
  }

  if (!mrb_test(aliving)) {
    ngx_mrb_fiber_unregister(fiber_proc);
    if (result != NULL) {
      *result = handler_result;
    }
  }

  return aliving;
}

static ngx_int_t ngx_mrb_post_fiber(ngx_mrb_reentrant_t *re, ngx_http_mruby_ctx_t *ctx)
{
  ngx_int_t rc = NGX_OK;
  ngx_http_mruby_handler_kind_t kind;
  int ai;

  ai = mrb_gc_arena_save(re->mrb);

  if (re->fiber != NULL) {
    // the handler that runs the fiber, for ngx_mrb_finalize_rputs below; read
    // before re->fiber is cleared
    kind = ((ngx_mrb_fiber_t *)re->fiber)->kind;
    ngx_mrb_push_request(re->r);
    re->r->headers_out.status = re->fiber_prev_status;

    if (mrb_test(ngx_mrb_run_fiber(re->mrb, re->fiber, ctx->async_handler_result))) {
      // can resume the fiber and wait the epoll timer
      mrb_gc_arena_restore(re->mrb, ai);
      return NGX_DONE;
    } else {
      // can not resume the fiber, the fiber was finished (ngx_mrb_run_fiber
      // has unregistered it)
      re->fiber = NULL;
    }

    if (re->mrb->exc) {
      ngx_mrb_raise_error(re->mrb, mrb_obj_value(re->mrb->exc), re->r);
      // all requests share this mrb_state: clear the exception as ngx_mrb_run
      // does (ngx_mrb_state_clean), or the next ngx_mrb_start_fiber fails
      // with it
      re->mrb->exc = NULL;
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
      rc = ngx_mrb_finalize_rputs(re->r, ctx, kind);
    }
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
  ngx_connection_t *c;
  ngx_int_t rc = NGX_OK;

#ifdef NGX_MRUBY_DEBUG_STATS
  ngx_mrb_async_debug_timers_count--;
#endif

  re = ev->data;
  // re is allocated from the request pool, which the finalization below can
  // destroy
  c = re->r->connection;
  ctx = ngx_mrb_http_get_module_ctx(NULL, re->r);

  if (ctx == NULL) {
    rc = NGX_ERROR;
  }
  rc = ngx_mrb_post_fiber(re, ctx);

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

static void ngx_mrb_async_sleep_cleanup(void *data)
{
  ngx_event_t *ev = (ngx_event_t *)data;

  if (ev->timer_set) {
#ifdef NGX_MRUBY_DEBUG_STATS
    ngx_mrb_async_debug_timers_count--;
#endif
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
  ngx_http_mruby_ctx_t *ctx;

  mrb_get_args(mrb, "i", &timer);

  if (timer <= 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "value of the timer must be a positive number");
  }

  r = ngx_mrb_async_request(mrb, "Nginx::Async.sleep");
  p = ngx_palloc(r->pool, sizeof(ngx_event_t) + sizeof(ngx_mrb_reentrant_t));
  re = (ngx_mrb_reentrant_t *)(p + sizeof(ngx_event_t));
  re->mrb = mrb;
  re->fiber_prev_status = r->headers_out.status;
  re->r = r;
  re->sr = NULL;

  ctx = ngx_mrb_http_get_module_ctx(mrb, r);
  re->fiber = ctx->fiber_proc;

  ev = (ngx_event_t *)p;
  ngx_memzero(ev, sizeof(ngx_event_t));
  ev->handler = ngx_mrb_timer_handler;
  ev->data = re;
  ev->log = ngx_cycle->log;

  ngx_add_timer(ev, (ngx_msec_t)timer);
#ifdef NGX_MRUBY_DEBUG_STATS
  ngx_mrb_async_debug_timers_count++;
#endif

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
  ngx_buf_t *buffer = NULL;
  ngx_int_t body_len = 0;

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
      ngx_memcpy(ctx->sub_response_body, buffer->pos, body_len);
      ctx->sub_response_body_length = body_len;
      ctx->sub_response_status = sr->headers_out.status;
      ctx->sub_response_headers = sr->headers_out;
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
  mrb_value path, query_params;
  ngx_str_t *args = NULL;
  int argc;

  argc = mrb_get_args(mrb, "o|S", &path, &query_params);

  r = ngx_mrb_async_request(mrb, "Nginx::Async::HTTP.sub_request");
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
    args = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    args->len = RSTRING_LEN(query_params);
    args->data = (u_char *)ngx_palloc(r->pool, RSTRING_LEN(query_params));
    ngx_memcpy(args->data, RSTRING_PTR(query_params), args->len);
  }

  re = (ngx_mrb_reentrant_t *)ngx_palloc(r->pool, sizeof(ngx_mrb_reentrant_t));
  re->mrb = mrb;
  re->fiber_prev_status = r->headers_out.status;
  re->sr = NULL;

  ctx = ngx_mrb_http_get_module_ctx(mrb, r);
  re->fiber = ctx->fiber_proc;

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
