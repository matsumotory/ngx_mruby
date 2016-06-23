/*
// ngx_http_mruby_core.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_core.h"
#include "ngx_http_mruby_module.h"
#include "ngx_http_mruby_request.h"

#include "mruby.h"
#include "mruby/array.h"
#include "mruby/compile.h"
#include "mruby/data.h"
#include "mruby/proc.h"
#include "mruby/string.h"
#include "mruby/variable.h"

#include <nginx.h>
#include <ngx_buf.h>
#include <ngx_conf_file.h>
#include <ngx_http.h>
#include <ngx_log.h>

ngx_module_t ngx_http_mruby_module;

void ngx_mrb_raise_error(mrb_state *mrb, mrb_value obj, ngx_http_request_t *r)
{
  struct RString *str;
  char *err_out;

  obj = mrb_funcall(mrb, obj, "inspect", 0);
  if (mrb_type(obj) == MRB_TT_STRING) {
    str = mrb_str_ptr(obj);
    err_out = str->as.heap.ptr;
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "mrb_run failed: return 500 HTTP status code to client: error: %s", err_out);
  }
}

void ngx_mrb_raise_cycle_error(mrb_state *mrb, mrb_value obj, ngx_cycle_t *cycle)
{
  struct RString *str;
  char *err_out;

  obj = mrb_funcall(mrb, obj, "inspect", 0);
  if (mrb_type(obj) == MRB_TT_STRING) {
    str = mrb_str_ptr(obj);
    err_out = str->as.heap.ptr;
    ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "mrb_run failed. error: %s", err_out);
  }
}

void ngx_mrb_raise_conf_error(mrb_state *mrb, mrb_value obj, ngx_conf_t *cf)
{
  struct RString *str;
  char *err_out;

  obj = mrb_funcall(mrb, obj, "inspect", 0);
  if (mrb_type(obj) == MRB_TT_STRING) {
    str = mrb_str_ptr(obj);
    err_out = str->as.heap.ptr;
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "mrb_run failed. error: %s", err_out);
  }
}

static mrb_value ngx_mrb_send_header(mrb_state *mrb, mrb_value self)
{
  ngx_mrb_rputs_chain_list_t *chain = NULL;
  ngx_http_mruby_ctx_t *ctx;

  ngx_http_request_t *r = ngx_mrb_get_request();
  mrb_int status = NGX_HTTP_OK;
  mrb_get_args(mrb, "i", &status);
  r->headers_out.status = status;

  ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);
  if (ctx == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s: get mruby context failed.", MODULE_NAME, __func__);
    mrb_raise(mrb, E_RUNTIME_ERROR, "get mruby context failed");
  }
  chain = ctx->rputs_chain;
  if (chain) {
    (*chain->last)->buf->last_buf = 1;
  }

  if (r->headers_out.status == NGX_HTTP_OK) {
    if (chain == NULL) {
      r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s: status code is 200, but response body is empty."
                                                        "Return NGX_HTTP_INTERNAL_SERVER_ERROR",
                    MODULE_NAME, __func__);
    }
  }

  return self;
}

static mrb_value ngx_mrb_rputs(mrb_state *mrb, mrb_value self)
{
  mrb_value argv;
  ngx_buf_t *b;
  ngx_mrb_rputs_chain_list_t *chain;
  u_char *str;
  ngx_str_t ns;

  ngx_http_request_t *r = ngx_mrb_get_request();
  ngx_http_mruby_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);

  mrb_get_args(mrb, "o", &argv);

  if (mrb_type(argv) != MRB_TT_STRING) {
    argv = mrb_funcall(mrb, argv, "to_s", 0, NULL);
  }

  ns.data = (u_char *)RSTRING_PTR(argv);
  ns.len = RSTRING_LEN(argv);
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
  str[ns.len] = '\0';
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

static mrb_value ngx_mrb_echo(mrb_state *mrb, mrb_value self)
{
  mrb_value argv;
  ngx_buf_t *b;
  ngx_mrb_rputs_chain_list_t *chain;
  u_char *str;
  ngx_str_t ns;

  ngx_http_request_t *r = ngx_mrb_get_request();
  ngx_http_mruby_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);

  mrb_get_args(mrb, "o", &argv);

  if (mrb_type(argv) != MRB_TT_STRING) {
    argv = mrb_funcall(mrb, argv, "to_s", 0, NULL);
  }

  ns.data = (u_char *)RSTRING_PTR(mrb_str_plus(mrb, argv, mrb_str_new_lit(mrb, "\n")));
  ns.len = RSTRING_LEN(argv) + sizeof("\n") - 1;
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
  str[ns.len] = '\0';
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

static mrb_value ngx_mrb_errlogger(mrb_state *mrb, mrb_value self)
{
  mrb_value *argv;
  mrb_value msg;
  mrb_int argc;
  mrb_int log_level;
  ngx_http_request_t *r = ngx_mrb_get_request();
  if (r == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't use logger at this phase. only use at request phase");
  }

  mrb_get_args(mrb, "*", &argv, &argc);
  if (argc != 2) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s: argument is not 2", MODULE_NAME, __func__);
    return self;
  }
  if (mrb_type(argv[0]) != MRB_TT_FIXNUM) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s: argv[0] is not integer", MODULE_NAME, __func__);
    return self;
  }
  log_level = mrb_fixnum(argv[0]);
  if (log_level < 0) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s: log level is not positive number", MODULE_NAME,
                  __func__);
    return self;
  }
  if (mrb_type(argv[1]) != MRB_TT_STRING) {
    msg = mrb_funcall(mrb, argv[1], "to_s", 0, NULL);
  } else {
    msg = mrb_str_dup(mrb, argv[1]);
  }
  ngx_log_error((ngx_uint_t)log_level, r->connection->log, 0, "%s", mrb_str_to_cstr(mrb, msg));

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
  u_char *str;
  ngx_int_t rc;
  mrb_value uri, code;
  ngx_str_t ns;
  ngx_table_elt_t *location;

  ngx_http_request_t *r = ngx_mrb_get_request();
  argc = mrb_get_args(mrb, "o|oo", &uri, &code);

  // get status code from args
  if (argc == 2) {
    rc = mrb_fixnum(code);
  } else {
    rc = NGX_HTTP_MOVED_TEMPORARILY;
  }

  // get redirect uri from args
  if (mrb_type(uri) != MRB_TT_STRING) {
    uri = mrb_funcall(mrb, uri, "to_s", 0, NULL);
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

    str = ngx_pstrdup(r->pool, &ns);
    if (str == NULL) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
    }
    str[ns.len] = '\0';

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

    // set location and response code for hreaders
    r->headers_out.location = location;
    r->headers_out.status = rc;
  } else {
    ngx_http_internal_redirect(r, &ns, &r->args);
    ngx_http_finalize_request(r, NGX_DONE);
  }

  return self;
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
  mrb_define_class_method(mrb, class, "log", ngx_mrb_errlogger, MRB_ARGS_ANY());
  mrb_define_class_method(mrb, class, "errlogger", ngx_mrb_errlogger, MRB_ARGS_ANY());
  mrb_define_class_method(mrb, class, "module_name", ngx_mrb_get_ngx_mruby_name, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, class, "module_version", ngx_mrb_get_ngx_mruby_version, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, class, "nginx_version", ngx_mrb_get_nginx_version, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, class, "server_version", ngx_mrb_get_nginx_version, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, class, "configure", ngx_http_mruby_get_nginx_configure, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, class, "redirect", ngx_mrb_redirect, MRB_ARGS_ANY());
  mrb_define_class_method(mrb, class, "remove_global_variable", ngx_mrb_f_global_remove, MRB_ARGS_REQ(1));
}
