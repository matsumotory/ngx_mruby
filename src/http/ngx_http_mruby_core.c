/*
// ngx_http_mruby_core.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_core.h"

#include "ngx_http_mruby_debug.h" // with NGX_MRUBY_DEBUG_STATS, counts the mrb_gc_register() calls
#include "ngx_http_mruby_gc_roots.h"
#include "ngx_http_mruby_module.h"
#include "ngx_http_mruby_request.h"

#include "mruby/array.h"
#include "mruby/error.h"
#include "mruby/string.h"
#include "mruby/variable.h"
#include "mruby/internal.h"
#include "mruby/presym.h"

ngx_http_mruby_syms_t ngx_http_mruby_syms;

// Interns the names of NGX_HTTP_MRUBY_SYM_LIST in mrb, and makes mrb the state
// of the table. ngx_http_mruby_sym() calls it the first time it is called with
// mrb. mrb_intern_cstr() is what the request path called before, so the
// symbol table gets the same entries.
void ngx_http_mruby_syms_fill(mrb_state *mrb)
{
#define NGX_HTTP_MRUBY_SYM_NAME(id, name) name,
  static const char *const names[NGX_HTTP_MRUBY_SYM_COUNT] = {NGX_HTTP_MRUBY_SYM_LIST(NGX_HTTP_MRUBY_SYM_NAME)};
#undef NGX_HTTP_MRUBY_SYM_NAME
  ngx_uint_t i;

  // mrb_intern_cstr() raises NoMemoryError when the symbol table cannot grow.
  // The table forgets the previous state before the loop writes ids of mrb, so
  // that it never names one state while it holds ids of another: after a
  // raise, the next call with any state fills it again.
  ngx_http_mruby_syms.mrb = NULL;
  for (i = 0; i < NGX_HTTP_MRUBY_SYM_COUNT; i++) {
    ngx_http_mruby_syms.sym[i] = mrb_intern_cstr(mrb, names[i]);
  }
  ngx_http_mruby_syms.mrb = mrb;
}

// Called by mrb_close() before it frees the state.
static void ngx_http_mruby_syms_forget(mrb_state *mrb)
{
  if (ngx_http_mruby_syms.mrb == mrb) {
    ngx_http_mruby_syms.mrb = NULL;
  }
}

// Called once for each mrb_state of the http module, right after mrb_open().
// It does not intern the names: see NGX_HTTP_MRUBY_SYM_LIST.
void ngx_http_mruby_syms_init(mrb_state *mrb)
{
  mrb_state_atexit(mrb, ngx_http_mruby_syms_forget);
}

#if (NGX_DEBUG)
static void ngx_mrb_log_backtrace(mrb_state *mrb, mrb_value obj, ngx_log_t *log)
{
  if (mrb_type(obj) == MRB_TT_EXCEPTION) {
    mrb_value bt = mrb_funcall_id(mrb, obj, MRB_SYM(backtrace), 0);
    if (mrb_type(bt) != MRB_TT_ARRAY) {
      ngx_log_error(NGX_LOG_DEBUG, log, 0, "backtrace must be Array. mrb_type=%d", mrb_type(bt));
      return;
    }
    const mrb_value *p = RARRAY_PTR(bt);
    const mrb_value *e = p + RARRAY_LEN(bt);
    while (p < e) {
      ngx_log_error(NGX_LOG_ERR, log, 0, "%*s", RSTRING_LEN(*p), RSTRING_PTR(*p));
      p++;
    }
  }
}
#endif

void ngx_mrb_raise_error(mrb_state *mrb, mrb_value exc, ngx_http_request_t *r)
{
  mrb_value s = mrb_funcall_id(mrb, exc, MRB_SYM(inspect), 0);
  if (mrb_type(s) == MRB_TT_STRING) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "mrb_run failed: return 500 HTTP status code to client: error: %*s", RSTRING_LEN(s), RSTRING_PTR(s));
  }
#if (NGX_DEBUG)
  ngx_mrb_log_backtrace(mrb, exc, r->connection->log);
#endif
}

void ngx_mrb_raise_connection_error(mrb_state *mrb, mrb_value exc, ngx_connection_t *c)
{
  mrb_value s = mrb_funcall_id(mrb, exc, MRB_SYM(inspect), 0);
  if (mrb_type(s) == MRB_TT_STRING) {
    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                  MODULE_NAME " : mrb_run failed: return 500 HTTP status code to client: error: %*s", RSTRING_LEN(s),
                  RSTRING_PTR(s));
  }
#if (NGX_DEBUG)
  ngx_mrb_log_backtrace(mrb, exc, c->log);
#endif
}

void ngx_mrb_raise_cycle_error(mrb_state *mrb, mrb_value exc, ngx_cycle_t *cycle)
{
  mrb_value s = mrb_funcall_id(mrb, exc, MRB_SYM(inspect), 0);
  if (mrb_type(s) == MRB_TT_STRING) {
    ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "mrb_run failed. error: %*s", RSTRING_LEN(s), RSTRING_PTR(s));
  }
#if (NGX_DEBUG)
  ngx_mrb_log_backtrace(mrb, exc, cycle->log);
#endif
}

void ngx_mrb_raise_conf_error(mrb_state *mrb, mrb_value exc, ngx_conf_t *cf)
{
  mrb_value s = mrb_funcall_id(mrb, exc, MRB_SYM(inspect), 0);
  if (mrb_type(s) == MRB_TT_STRING) {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "mrb_run failed. error: %*s", RSTRING_LEN(s), RSTRING_PTR(s));
  }
#if (NGX_DEBUG)
  ngx_mrb_log_backtrace(mrb, exc, cf->log);
#endif
}

/*
 * Whether a content handler would leave the client without a response if
 * ngx_mrb_finalize_rputs returned the status: when it ended without output,
 * or when it wrote output and then set the status with Nginx.return,
 * Nginx.send_header or Nginx.status_code=. The content phase hands the value
 * that the handler returns to ngx_http_finalize_request, which answers 201,
 * 204 and the statuses from 300 up by itself, but ends the request without
 * sending anything for NGX_OK and the other statuses below 300: nginx closes
 * an HTTP/1.0 connection without a byte and keeps a keep-alive connection
 * open until keepalive_timeout. Without output, this covers a handler that
 * sets no status (it writes nothing, or only an empty String or nil with
 * Nginx.rputs), 200 and the other such statuses; ngx_mrb_finalize_rputs
 * answers them. After output, a 200 is sent with the output, and so is
 * another such status.
 *
 * Only the main request: a subrequest, with or without output, does not leave the
 * client without a response, because its parent answers. Nothing changes
 * either when the header was already sent, or when the module context is no
 * longer the one the handler ran with: Nginx.redirect makes an internal
 * redirect, which clears the module contexts, and the location it ran answers
 * the request.
 */
static ngx_flag_t ngx_mrb_content_ends_without_response(ngx_http_request_t *r, ngx_http_mruby_ctx_t *ctx,
                                                        ngx_http_mruby_handler_kind_t kind)
{
  ngx_uint_t status = r->headers_out.status;

  if (kind != NGX_HTTP_MRUBY_HANDLER_CONTENT || r != r->main || r->header_sent ||
      ngx_http_get_module_ctx(r, ngx_http_mruby_module) != ctx) {
    return 0;
  }

  // Nginx.return with a negative value such as Nginx::DECLINED stores a status
  // that wraps around above this range, and ngx_mrb_finalize_rputs returns it
  // as that value
  return status < NGX_HTTP_SPECIAL_RESPONSE && status != NGX_HTTP_CREATED && status != NGX_HTTP_NO_CONTENT;
}

// Answers 500 for a content handler that ended without output and with a
// status below 200, which nginx cannot send as the status of a final
// response, and logs why
static ngx_int_t ngx_mrb_answer_missing_body(ngx_http_request_t *r)
{
  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "%s ERROR %s: status code is %ui, but response body is empty."
                " return NGX_HTTP_INTERNAL_SERVER_ERROR",
                MODULE_NAME, __func__, r->headers_out.status);

  r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;

  return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

/*
 * Discards a request body that no handler read before the response starts,
 * as nginx's own handlers do (ngx_http_send_response, the special
 * responses): nginx then reads the next request of a kept connection after
 * the body, not from it. A body that a handler read is left alone
 * (r->request_body is set), and so is the request after the header went out.
 * If the body cannot be discarded, the connection is closed after the
 * response, as in ngx_http_special_response_handler. Both answers of
 * ngx_mrb_finalize_rputs call it: the one with output and the empty one.
 */
static void ngx_mrb_discard_unread_body(ngx_http_request_t *r)
{
  if (!r->header_sent && ngx_http_discard_request_body(r) != NGX_OK) {
    r->keepalive = 0;
  }
}

/*
 * Answers a content handler that ended without output and set no status, 200
 * or another status below 300 that nginx does not answer by itself, as
 * nginx's "return 200;" does (ngx_http_send_response): with that status, 200
 * when none is set, Content-Length: 0 and an empty body (#200). nginx then
 * keeps a keep-alive connection for the next request, after it discarded a
 * request body that no handler read, as for the answer with output.
 *
 * It sends the response the way ngx_mrb_finalize_rputs sends one with output,
 * so the header filters and the body filters of the location see it, and it
 * returns NGX_OK once the header went out: the mruby filters return
 * NGX_ERROR after they passed on the header of a response without a body (a
 * HEAD request), which must not end the request. Only a header that did not
 * go out returns the result of ngx_http_send_header, for the content phase
 * to finalize the request with. The chain is not kept in the module context,
 * so that a filter that runs ngx_mrb_run finds no rputs chain and only
 * returns the status. The empty buffer is not in memory, so that the filters
 * and the writer take it for the end of the response and not for a zero size
 * buffer.
 */
static ngx_int_t ngx_mrb_send_empty_body(ngx_http_request_t *r)
{
  ngx_int_t rc;
  ngx_buf_t *b;
  ngx_chain_t out;

  b = ngx_calloc_buf(r->pool);
  if (b == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory from r->pool %s:%d", __FUNCTION__,
                  __LINE__);
    r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  b->last_buf = 1;
  b->last_in_chain = 1;
  out.buf = b;
  out.next = NULL;

  if (r->headers_out.status == 0) {
    r->headers_out.status = NGX_HTTP_OK;
  }
  r->headers_out.content_length_n = 0;

  ngx_mrb_discard_unread_body(r);
  rc = ngx_http_send_header(r);

  if ((rc == NGX_ERROR || rc > NGX_OK) && !r->header_sent) {
    return rc;
  }

  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    return NGX_OK;
  }

  ngx_http_output_filter(r, &out);

  return NGX_OK;
}

// TODO: Support rputs by multi directive
ngx_int_t ngx_mrb_finalize_rputs(ngx_http_request_t *r, ngx_http_mruby_ctx_t *ctx, ngx_http_mruby_handler_kind_t kind)
{
  ngx_int_t rc = NGX_OK;
  ngx_mrb_rputs_chain_list_t *chain;

  chain = ctx->rputs_chain;

  if (chain == NULL) {
    if (ngx_mrb_content_ends_without_response(r, ctx, kind)) {
      if (r->headers_out.status == 0 || r->headers_out.status >= NGX_HTTP_OK) {
        return ngx_mrb_send_empty_body(r);
      }
      return ngx_mrb_answer_missing_body(r);
    }
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "%s INFO %s:%d: mrb_run info: rputs_chain is null and return NGX_OK", MODULE_NAME, __func__,
                  __LINE__);
    if (r->headers_out.status >= 100) {
      rc = r->headers_out.status;
    } else {
      rc = NGX_OK;
    }
  } else if (r->headers_out.status == NGX_HTTP_OK || !(*chain->last)->buf->last_buf ||
             ngx_mrb_content_ends_without_response(r, ctx, kind)) {
    // A status set after the output marks the last buffer. nginx answers 201,
    // 204 and the statuses from 300 up by itself (the else branch below), but
    // would end the request without a response for another status below 300:
    // the output goes out with that status, as nginx's own "return 202 text"
    // sends it. 0 is no status, and the output gets 200, as when the status
    // was set before the output.
    if (!(*chain->last)->buf->last_buf || r->headers_out.status == 0) {
      r->headers_out.status = NGX_HTTP_OK;
    }
    (*chain->last)->buf->last_buf = 1;
    ngx_mrb_discard_unread_body(r);
    ngx_http_send_header(r);

    // A HEAD request must receive the headers only; nginx sets r->header_only.
    // Do not send the body chain for it, as nginx's own content handlers skip
    // the body after ngx_http_send_header when r->header_only is set. The
    // headers, Content-Length included, are already set, so the HEAD response
    // still reports the length the body would have had.
    if (ctx->phase != NGX_HTTP_MRUBY_FILTER_PROCESS && !r->header_only) {
      ngx_http_output_filter(r, chain->out);
    }

    ngx_http_set_ctx(r, NULL, ngx_http_mruby_module);
    rc = NGX_OK;
  } else {
    rc = r->headers_out.status;
  }

  return rc;
}

ngx_int_t ngx_mrb_finalize_body_filter(ngx_http_request_t *r, ngx_http_mruby_ctx_t *ctx)
{
  ngx_buf_t *b;
  ngx_int_t rc;
  ngx_chain_t out;

  b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
  if (b == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory from r->pool %s:%d", __FUNCTION__,
                  __LINE__);
    return NGX_ERROR;
  }

  b->pos = ctx->body;
  b->last = ctx->body + ctx->body_length;
  // A buffer without bytes is not marked as memory, as in
  // ngx_http_send_response: nginx's filters and writer reject a zero size
  // buffer in memory ("zero size buf in writer"), and the response would end
  // without being sent. A body filter gets an empty body when the response has
  // none, for example the empty 200 of a content handler without output, or
  // when it sets one.
  b->memory = ctx->body_length ? 1 : 0;
  b->last_buf = 1;

  r->headers_out.content_length_n = b->last - b->pos;

  if (r->headers_out.content_length) {
    r->headers_out.content_length->hash = 0;
  }

  r->headers_out.content_length = NULL;

  out.buf = b;
  out.next = NULL;
  ctx->phase = NGX_HTTP_MRUBY_FILTER_PASS;

  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "%s DEBUG %s:%d: data after body length: %uz", MODULE_NAME,
                __func__, __LINE__, ctx->body_length);

  rc = ngx_http_next_header_filter(r);

  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    return NGX_ERROR;
  }

  return ngx_http_next_body_filter(r, &out);
}

static mrb_value ngx_mrb_send_header(mrb_state *mrb, mrb_value self)
{
  ngx_mrb_rputs_chain_list_t *chain = NULL;
  ngx_http_mruby_ctx_t *ctx;

  ngx_http_request_t *r = ngx_mrb_get_request_or_raise(mrb);
  mrb_int status = NGX_HTTP_OK;
  mrb_get_args(mrb, "i", &status);
  r->headers_out.status = status;

  ctx = ngx_mrb_http_get_module_ctx(mrb, r);

  chain = ctx->rputs_chain;
  if (chain) {
    (*chain->last)->buf->last_buf = 1;
  }

  // In a content handler of the main request, ngx_mrb_finalize_rputs answers
  // 200 without output with an empty body when the handler ends, so the
  // status stays 200 there. The other handlers and subrequests answer 500, as
  // the 2.x line does.
  if (r->headers_out.status == NGX_HTTP_OK && !(ctx->handler_kind == NGX_HTTP_MRUBY_HANDLER_CONTENT && r == r->main)) {
    if (chain == NULL) {
      r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "%s ERROR %s: status code is 200, but response body is empty."
                    " return NGX_HTTP_INTERNAL_SERVER_ERROR",
                    MODULE_NAME, __func__);
    }
  }

  return self;
}

static mrb_value ngx_mrb_rputs_inner(mrb_state *mrb, mrb_value self, int with_lf)
{
  mrb_value argv;
  ngx_buf_t *b;
  ngx_mrb_rputs_chain_list_t *chain;
  ngx_http_mruby_ctx_t *ctx;
  u_char *str;
  ngx_str_t ns;

  ngx_http_request_t *r = ngx_mrb_get_request_or_raise(mrb);
  ctx = ngx_mrb_http_get_module_ctx(mrb, r);

  mrb_get_args(mrb, "o", &argv);

  if (mrb_type(argv) != MRB_TT_STRING) {
    argv = mrb_funcall_id(mrb, argv, MRB_SYM(to_s), 0);
  }

  if (with_lf) {
    ns.data = (u_char *)RSTRING_PTR(mrb_str_plus(mrb, argv, mrb_str_new_lit(mrb, "\n")));
    ns.len = RSTRING_LEN(argv) + sizeof("\n") - 1;
  } else {
    ns.data = (u_char *)RSTRING_PTR(argv);
    ns.len = RSTRING_LEN(argv);
  }
  if (ns.len == 0) {
    return self;
  }

  if (ctx->rputs_chain == NULL) {
    chain = ngx_pcalloc(r->pool, sizeof(ngx_mrb_rputs_chain_list_t));
    if (chain == NULL) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
    }
    chain->out = ngx_alloc_chain_link(r->pool);
    if (chain->out == NULL) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
    }
    chain->last = &chain->out;
    chain->content_length_n = r->headers_out.content_length_n;
  } else {
    chain = ctx->rputs_chain;
    (*chain->last)->next = ngx_alloc_chain_link(r->pool);
    if ((*chain->last)->next == NULL) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
    }
    chain->last = &(*chain->last)->next;
  }
  b = ngx_calloc_buf(r->pool);
  if (b == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
  }
  (*chain->last)->buf = b;
  (*chain->last)->next = NULL;

  str = ngx_pstrdup(r->pool, &ns);
  if (str == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
  }
  (*chain->last)->buf->pos = str;
  (*chain->last)->buf->last = str + ns.len;
  (*chain->last)->buf->memory = 1;
  ctx->rputs_chain = chain;
  ngx_http_set_ctx(r, ctx, ngx_http_mruby_module);

  if (r->headers_out.content_length_n == -1) {
    r->headers_out.content_length_n += ns.len + 1;
  } else {
    r->headers_out.content_length_n += ns.len;
  }

  return self;
}

static mrb_value ngx_mrb_rputs(mrb_state *mrb, mrb_value self)
{
  int with_lf = 0;
  return ngx_mrb_rputs_inner(mrb, self, with_lf);
}

static mrb_value ngx_mrb_echo(mrb_state *mrb, mrb_value self)
{
  int with_lf = 1;
  return ngx_mrb_rputs_inner(mrb, self, with_lf);
}

static mrb_value ngx_mrb_errlogger(mrb_state *mrb, mrb_value self)
{
  mrb_value msg;
  mrb_int log_level;
  ngx_http_request_t *r = ngx_mrb_get_request();
  /* outside of a request (init_worker, exit_worker, SSL handshake) log to the cycle's log */
  ngx_log_t *log = (r != NULL) ? r->connection->log : ngx_cycle->log;

  mrb_get_args(mrb, "io", &log_level, &msg);
  if (log_level < 0) {
    ngx_log_error(NGX_LOG_ERR, log, 0, "%s ERROR %s: log level is not positive number", MODULE_NAME, __func__);
    return self;
  }
  msg = mrb_obj_as_string(mrb, msg);
  ngx_log_error((ngx_uint_t)log_level, log, 0, "%*s", RSTRING_LEN(msg), RSTRING_PTR(msg));

  return self;
}

static mrb_value ngx_mrb_get_ngx_mruby_name(mrb_state *mrb, mrb_value self)
{
  return mrb_str_new_lit(mrb, MODULE_NAME);
}

static mrb_value ngx_mrb_get_ngx_mruby_version(mrb_state *mrb, mrb_value self)
{
  return mrb_str_new_lit(mrb, MODULE_VERSION);
}

static mrb_value ngx_mrb_get_nginx_version(mrb_state *mrb, mrb_value self)
{
  return mrb_str_new_lit(mrb, NGINX_VERSION);
}

static mrb_value ngx_mrb_server_name(mrb_state *mrb, mrb_value self)
{
  return mrb_str_new_lit(mrb, NGINX_VAR);
}

static mrb_value ngx_http_mruby_get_nginx_configure(mrb_state *mrb, mrb_value self)
{
  return mrb_str_new_lit(mrb, NGX_CONFIGURE);
}

// like Nginx rewrite keywords
// used like this:
// => http code 3xx location in browser
// => internal redirection in nginx
static mrb_value ngx_mrb_redirect(mrb_state *mrb, mrb_value self)
{
  int argc;
  ngx_int_t rc;
  mrb_value uri, code;
  ngx_str_t ns;
  ngx_table_elt_t *location;

  ngx_http_request_t *r = ngx_mrb_get_request_or_raise(mrb);
  argc = mrb_get_args(mrb, "o|oo", &uri, &code);

  // get status code from args
  if (argc == 2) {
    rc = mrb_fixnum(code);
  } else {
    rc = NGX_HTTP_MOVED_TEMPORARILY;
  }

  // get redirect uri from args
  if (mrb_type(uri) != MRB_TT_STRING) {
    uri = mrb_funcall_id(mrb, uri, MRB_SYM(to_s), 0);
  }

  // save location uri to ns
  ns.len = RSTRING_LEN(uri);
  if (ns.len == 0) {
    return mrb_nil_value();
  }
  ns.data = ngx_palloc(r->pool, ns.len);
  ngx_memcpy(ns.data, RSTRING_PTR(uri), ns.len);

  // if uri start with scheme prefix
  // return 3xx for redirect
  // else generate a internal redirection and response to raw request
  // request.path is not changed
  if (ngx_strncmp(ns.data, "http://", sizeof("http://") - 1) == 0 ||
      ngx_strncmp(ns.data, "https://", sizeof("https://") - 1) == 0 ||
      ngx_strncmp(ns.data, "$scheme", sizeof("$scheme") - 1) == 0) {

    // build redirect location
    location = ngx_list_push(&r->headers_out.headers);
    if (location == NULL) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
    }
    location->hash = 1;
    ngx_str_set(&location->key, "Location");
    location->value = ns;
    location->lowcase_key = ngx_pnalloc(r->pool, location->value.len);
    if (location->lowcase_key == NULL) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
    }
    ngx_strlow(location->lowcase_key, location->value.data, location->value.len);

    // set location and response code for headers
    r->headers_out.location = location;
    r->headers_out.status = rc;
  } else {
    ngx_http_internal_redirect(r, &ns, &r->args);
  }

  return self;
}

ngx_http_mruby_ctx_t *ngx_mrb_http_get_module_ctx(mrb_state *mrb, ngx_http_request_t *r)
{
  ngx_http_mruby_ctx_t *ctx;
  ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);
  if (ctx == NULL) {
    if ((ctx = ngx_pcalloc(r->pool, sizeof(*ctx))) == NULL) {
      if (mrb != NULL) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate context");
      } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "failed to allocate memory from r->pool(mrb_state is a nonexistent directive) %s:%d",
                      __FUNCTION__, __LINE__);
        return NULL;
      }
    }
    ctx->body = NULL;
    ngx_http_set_ctx(r, ctx, ngx_http_mruby_module);
  }
  return ctx;
}

mrb_value ngx_mrb_f_global_remove(mrb_state *mrb, mrb_value self)
{
  mrb_sym id;
  mrb_get_args(mrb, "n", &id);
  mrb_gv_remove(mrb, id);

  return mrb_f_global_variables(mrb, self);
}

void ngx_mrb_core_class_init(mrb_state *mrb, struct RClass *class)
{
  mrb_define_method(mrb, mrb->kernel_module, "server_name", ngx_mrb_server_name, MRB_ARGS_NONE());

  mrb_define_const(mrb, class, "TRUE", mrb_str_new_lit(mrb, "1"));
  mrb_define_const(mrb, class, "FALSE", mrb_str_new_lit(mrb, "0"));

  mrb_define_const(mrb, class, "OK", mrb_fixnum_value(NGX_OK));
  mrb_define_const(mrb, class, "ERROR", mrb_fixnum_value(NGX_ERROR));
  mrb_define_const(mrb, class, "AGAIN", mrb_fixnum_value(NGX_AGAIN));
  mrb_define_const(mrb, class, "BUSY", mrb_fixnum_value(NGX_BUSY));
  mrb_define_const(mrb, class, "DONE", mrb_fixnum_value(NGX_DONE));
  mrb_define_const(mrb, class, "DECLINED", mrb_fixnum_value(NGX_DECLINED));
  mrb_define_const(mrb, class, "ABORT", mrb_fixnum_value(NGX_ABORT));
  mrb_define_const(mrb, class, "HTTP_CONTINUE", mrb_fixnum_value(NGX_HTTP_CONTINUE));
  mrb_define_const(mrb, class, "HTTP_SWITCHING_PROTOCOLS", mrb_fixnum_value(NGX_HTTP_SWITCHING_PROTOCOLS));
  mrb_define_const(mrb, class, "HTTP_PROCESSING", mrb_fixnum_value(NGX_HTTP_PROCESSING));
  mrb_define_const(mrb, class, "HTTP_OK", mrb_fixnum_value(NGX_HTTP_OK));
  mrb_define_const(mrb, class, "HTTP_CREATED", mrb_fixnum_value(NGX_HTTP_CREATED));
  mrb_define_const(mrb, class, "HTTP_ACCEPTED", mrb_fixnum_value(NGX_HTTP_ACCEPTED));
  mrb_define_const(mrb, class, "HTTP_NO_CONTENT", mrb_fixnum_value(NGX_HTTP_NO_CONTENT));
  mrb_define_const(mrb, class, "HTTP_PARTIAL_CONTENT", mrb_fixnum_value(NGX_HTTP_PARTIAL_CONTENT));
  mrb_define_const(mrb, class, "HTTP_SPECIAL_RESPONSE", mrb_fixnum_value(NGX_HTTP_SPECIAL_RESPONSE));
  mrb_define_const(mrb, class, "HTTP_MOVED_PERMANENTLY", mrb_fixnum_value(NGX_HTTP_MOVED_PERMANENTLY));
  mrb_define_const(mrb, class, "HTTP_MOVED_TEMPORARILY", mrb_fixnum_value(NGX_HTTP_MOVED_TEMPORARILY));
  mrb_define_const(mrb, class, "HTTP_SEE_OTHER", mrb_fixnum_value(NGX_HTTP_SEE_OTHER));
  mrb_define_const(mrb, class, "HTTP_NOT_MODIFIED", mrb_fixnum_value(NGX_HTTP_NOT_MODIFIED));
  mrb_define_const(mrb, class, "HTTP_TEMPORARY_REDIRECT", mrb_fixnum_value(NGX_HTTP_TEMPORARY_REDIRECT));
  mrb_define_const(mrb, class, "HTTP_BAD_REQUEST", mrb_fixnum_value(NGX_HTTP_BAD_REQUEST));
  mrb_define_const(mrb, class, "HTTP_UNAUTHORIZED", mrb_fixnum_value(NGX_HTTP_UNAUTHORIZED));
  mrb_define_const(mrb, class, "HTTP_FORBIDDEN", mrb_fixnum_value(NGX_HTTP_FORBIDDEN));
  mrb_define_const(mrb, class, "HTTP_NOT_FOUND", mrb_fixnum_value(NGX_HTTP_NOT_FOUND));
  mrb_define_const(mrb, class, "HTTP_NOT_ALLOWED", mrb_fixnum_value(NGX_HTTP_NOT_ALLOWED));
  mrb_define_const(mrb, class, "HTTP_REQUEST_TIME_OUT", mrb_fixnum_value(NGX_HTTP_REQUEST_TIME_OUT));
  mrb_define_const(mrb, class, "HTTP_CONFLICT", mrb_fixnum_value(NGX_HTTP_CONFLICT));
  mrb_define_const(mrb, class, "HTTP_LENGTH_REQUIRED", mrb_fixnum_value(NGX_HTTP_LENGTH_REQUIRED));
  mrb_define_const(mrb, class, "HTTP_PRECONDITION_FAILED", mrb_fixnum_value(NGX_HTTP_PRECONDITION_FAILED));
  mrb_define_const(mrb, class, "HTTP_REQUEST_ENTITY_TOO_LARGE", mrb_fixnum_value(NGX_HTTP_REQUEST_ENTITY_TOO_LARGE));
  mrb_define_const(mrb, class, "HTTP_REQUEST_URI_TOO_LARGE", mrb_fixnum_value(NGX_HTTP_REQUEST_URI_TOO_LARGE));
  mrb_define_const(mrb, class, "HTTP_UNSUPPORTED_MEDIA_TYPE", mrb_fixnum_value(NGX_HTTP_UNSUPPORTED_MEDIA_TYPE));
  mrb_define_const(mrb, class, "HTTP_RANGE_NOT_SATISFIABLE", mrb_fixnum_value(NGX_HTTP_RANGE_NOT_SATISFIABLE));
  mrb_define_const(mrb, class, "HTTP_TOO_MANY_REQUESTS", mrb_fixnum_value(NGX_HTTP_TOO_MANY_REQUESTS));
  mrb_define_const(mrb, class, "HTTP_CLOSE", mrb_fixnum_value(NGX_HTTP_CLOSE));
  mrb_define_const(mrb, class, "HTTP_NGINX_CODES", mrb_fixnum_value(NGX_HTTP_NGINX_CODES));
  mrb_define_const(mrb, class, "HTTP_REQUEST_HEADER_TOO_LARGE", mrb_fixnum_value(NGX_HTTP_REQUEST_HEADER_TOO_LARGE));
  mrb_define_const(mrb, class, "HTTPS_CERT_ERROR", mrb_fixnum_value(NGX_HTTPS_CERT_ERROR));
  mrb_define_const(mrb, class, "HTTPS_NO_CERT", mrb_fixnum_value(NGX_HTTPS_NO_CERT));
  mrb_define_const(mrb, class, "HTTP_TO_HTTPS", mrb_fixnum_value(NGX_HTTP_TO_HTTPS));
  mrb_define_const(mrb, class, "HTTP_CLIENT_CLOSED_REQUEST", mrb_fixnum_value(NGX_HTTP_CLIENT_CLOSED_REQUEST));
  mrb_define_const(mrb, class, "HTTP_INTERNAL_SERVER_ERROR", mrb_fixnum_value(NGX_HTTP_INTERNAL_SERVER_ERROR));
  mrb_define_const(mrb, class, "HTTP_NOT_IMPLEMENTED", mrb_fixnum_value(NGX_HTTP_NOT_IMPLEMENTED));
  mrb_define_const(mrb, class, "HTTP_BAD_GATEWAY", mrb_fixnum_value(NGX_HTTP_BAD_GATEWAY));
  mrb_define_const(mrb, class, "HTTP_SERVICE_UNAVAILABLE", mrb_fixnum_value(NGX_HTTP_SERVICE_UNAVAILABLE));
  mrb_define_const(mrb, class, "HTTP_GATEWAY_TIME_OUT", mrb_fixnum_value(NGX_HTTP_GATEWAY_TIME_OUT));
  mrb_define_const(mrb, class, "HTTP_INSUFFICIENT_STORAGE", mrb_fixnum_value(NGX_HTTP_INSUFFICIENT_STORAGE));
  // error log priority
  mrb_define_const(mrb, class, "LOG_STDERR", mrb_fixnum_value(NGX_LOG_STDERR));
  mrb_define_const(mrb, class, "LOG_EMERG", mrb_fixnum_value(NGX_LOG_EMERG));
  mrb_define_const(mrb, class, "LOG_ALERT", mrb_fixnum_value(NGX_LOG_ALERT));
  mrb_define_const(mrb, class, "LOG_CRIT", mrb_fixnum_value(NGX_LOG_CRIT));
  mrb_define_const(mrb, class, "LOG_ERR", mrb_fixnum_value(NGX_LOG_ERR));
  mrb_define_const(mrb, class, "LOG_WARN", mrb_fixnum_value(NGX_LOG_WARN));
  mrb_define_const(mrb, class, "LOG_NOTICE", mrb_fixnum_value(NGX_LOG_NOTICE));
  mrb_define_const(mrb, class, "LOG_INFO", mrb_fixnum_value(NGX_LOG_INFO));
  mrb_define_const(mrb, class, "LOG_DEBUG", mrb_fixnum_value(NGX_LOG_DEBUG));

  mrb_define_class_method(mrb, class, "rputs", ngx_mrb_rputs, MRB_ARGS_ANY());
  mrb_define_class_method(mrb, class, "echo", ngx_mrb_echo, MRB_ARGS_ANY());
  mrb_define_class_method(mrb, class, "send_header", ngx_mrb_send_header, MRB_ARGS_ANY());
  mrb_define_class_method(mrb, class, "return", ngx_mrb_send_header, MRB_ARGS_ANY());
  mrb_define_class_method(mrb, class, "status_code=", ngx_mrb_send_header, MRB_ARGS_REQ(1));

  mrb_define_class_method(mrb, class, "log", ngx_mrb_errlogger, MRB_ARGS_REQ(2));
  mrb_define_class_method(mrb, class, "errlogger", ngx_mrb_errlogger, MRB_ARGS_REQ(2));
  mrb_define_class_method(mrb, class, "module_name", ngx_mrb_get_ngx_mruby_name, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, class, "module_version", ngx_mrb_get_ngx_mruby_version, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, class, "nginx_version", ngx_mrb_get_nginx_version, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, class, "server_version", ngx_mrb_get_nginx_version, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, class, "configure", ngx_http_mruby_get_nginx_configure, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, class, "redirect", ngx_mrb_redirect, MRB_ARGS_ANY());
  mrb_define_class_method(mrb, class, "remove_global_variable", ngx_mrb_f_global_remove, MRB_ARGS_REQ(1));
}

/*
// The holders of ngx_http_mruby_gc_roots.h, one per mrb_state, in a list
// that has one entry for the state of the http module and one for the state
// of the stream module, and for a while two more when nginx reads a new
// configuration. The entry of a state leaves the list when mrb_close() runs
// the atexit functions, before mruby frees the Array. With at most four
// entries, walking the list costs a few comparisons per fiber, less than a
// field of each mrb_state would cost to reach from the http and the stream
// code.
*/
typedef struct ngx_mrb_gc_roots_s {
  mrb_state *mrb;
  mrb_value ary;
  mrb_int free;
  struct ngx_mrb_gc_roots_s *next;
} ngx_mrb_gc_roots_t;

static ngx_mrb_gc_roots_t *ngx_mrb_gc_roots_list = NULL;

static ngx_mrb_gc_roots_t *ngx_mrb_gc_roots_find(mrb_state *mrb)
{
  ngx_mrb_gc_roots_t *h;

  for (h = ngx_mrb_gc_roots_list; h != NULL; h = h->next) {
    if (h->mrb == mrb) {
      return h;
    }
  }
  return NULL;
}

static void ngx_mrb_gc_roots_forget(mrb_state *mrb)
{
  ngx_mrb_gc_roots_t **p, *h;

  for (p = &ngx_mrb_gc_roots_list; (h = *p) != NULL; p = &h->next) {
    if (h->mrb == mrb) {
      *p = h->next;
      mrb_free(mrb, h);
      return;
    }
  }
}

static mrb_value ngx_mrb_gc_roots_new(mrb_state *mrb, void *data)
{
  mrb_value ary = mrb_ary_new(mrb);

  /* hidden from ObjectSpace.each_object, as mruby hides its own _gc_root_,
     so that no script can reach the holder */
  mrb_obj_ptr(ary)->c = NULL;
  mrb_gc_register(mrb, ary);
  return ary;
}

ngx_int_t ngx_mrb_gc_roots_init(mrb_state *mrb)
{
  ngx_mrb_gc_roots_t *h;
  mrb_value ary;
  mrb_bool raised;
  int ai;

  if (ngx_mrb_gc_roots_find(mrb) != NULL) {
    return NGX_OK;
  }
  h = mrb_malloc_simple(mrb, sizeof(ngx_mrb_gc_roots_t));
  if (h == NULL) {
    return NGX_ERROR;
  }
  ai = mrb_gc_arena_save(mrb);
  ary = mrb_protect_error(mrb, ngx_mrb_gc_roots_new, NULL, &raised);
  mrb_gc_arena_restore(mrb, ai);
  if (raised) {
    mrb_free(mrb, h);
    return NGX_ERROR;
  }
  h->mrb = mrb;
  h->ary = ary;
  h->free = NGX_MRB_GC_ROOTS_NONE;
  h->next = ngx_mrb_gc_roots_list;
  ngx_mrb_gc_roots_list = h;
  mrb_state_atexit(mrb, ngx_mrb_gc_roots_forget);

  return NGX_OK;
}

mrb_int ngx_mrb_gc_roots_add(mrb_state *mrb, mrb_value obj)
{
  ngx_mrb_gc_roots_t *h;
  mrb_int slot;

  if (mrb_immediate_p(obj)) {
    return NGX_MRB_GC_ROOTS_NONE;
  }
  h = ngx_mrb_gc_roots_find(mrb);
  if (h == NULL) {
    /* every state gets its holder when it is opened, so this is a bug */
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "ngx_mruby: no GC root holder for the mrb_state");
    return NGX_MRB_GC_ROOTS_NONE;
  }
  /* The holder lives as long as the state, so it is old (black) after the
     first GC. mrb_ary_set() and mrb_ary_push() would then add obj to the gray
     objects (mrb_field_write_barrier), and the next GC would mark the fiber
     and, in a minor GC, promote it and what it references to the old
     generation, also when the fiber has ended before that GC: such objects
     are freed only by a major GC. Painting the holder gray instead
     (mrb_write_barrier), as mrb_ary_modify() does, has the GC scan the
     holder again before the mark ends, which marks only the objects that are
     still in it. */
  mrb_write_barrier(mrb, mrb_basic_ptr(h->ary));
  if (h->free >= 0 && h->free < RARRAY_LEN(h->ary) && mrb_integer_p(RARRAY_PTR(h->ary)[h->free])) {
    slot = h->free;
    h->free = mrb_integer(RARRAY_PTR(h->ary)[slot]);
    mrb_ary_set(mrb, h->ary, slot, obj);
  } else {
    /* no free slot (a free list that does not lead to a free slot would be a
       bug: it is dropped, and the Array grows) */
    h->free = NGX_MRB_GC_ROOTS_NONE;
    slot = RARRAY_LEN(h->ary);
    mrb_ary_push(mrb, h->ary, obj);
  }
#ifdef NGX_MRUBY_DEBUG_STATS
  ngx_mrb_debug_gc_root_track(obj, 1);
#endif

  return slot;
}

void ngx_mrb_gc_roots_remove(mrb_state *mrb, mrb_int slot)
{
  ngx_mrb_gc_roots_t *h;

  if (slot == NGX_MRB_GC_ROOTS_NONE) {
    return;
  }
  h = ngx_mrb_gc_roots_find(mrb);
  if (h == NULL || slot < 0 || slot >= RARRAY_LEN(h->ary)) {
    return;
  }
  /* a free slot holds an Integer: a second release of the same slot would
     put it on the free list twice */
  if (mrb_integer_p(RARRAY_PTR(h->ary)[slot])) {
    return;
  }
#ifdef NGX_MRUBY_DEBUG_STATS
  ngx_mrb_debug_gc_root_track(RARRAY_PTR(h->ary)[slot], -1);
#endif
  mrb_ary_set(mrb, h->ary, slot, mrb_fixnum_value(h->free));
  h->free = slot;
}
