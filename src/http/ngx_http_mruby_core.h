/*
// ngx_http_mruby_core.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_CORE_H
#define NGX_HTTP_MRUBY_CORE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <mruby.h>

#define NGX_HTTP_MRUBY_FILTER_START 0
#define NGX_HTTP_MRUBY_FILTER_READ 1
#define NGX_HTTP_MRUBY_FILTER_PROCESS 2
#define NGX_HTTP_MRUBY_FILTER_PASS 3
#define NGX_HTTP_MRUBY_FILTER_DONE 4

typedef struct ngx_mrb_rputs_chain_list_t {
  ngx_chain_t **last;
  ngx_chain_t *out;
} ngx_mrb_rputs_chain_list_t;

/*
 * The kind of mruby handler whose fiber runs. Nginx::Async.sleep and
 * Nginx::Async::HTTP.sub_request suspend that fiber, and nginx resumes it
 * later from a timer or from the end of a subrequest. That works for mruby_set
 * and the post_read, server_rewrite, rewrite and access handlers. The content
 * handler is allowed too, only so that its behavior does not change. A log
 * handler runs in ngx_http_free_request after the request cleanups and right
 * before the request pool is destroyed, and a filter runs inside
 * ngx_http_send_header or ngx_http_output_filter, which return to their
 * caller, so Nginx::Async raises in those handlers and where no handler fiber
 * runs (NGX_HTTP_MRUBY_HANDLER_NONE, the value of a new context).
 */
typedef enum {
  NGX_HTTP_MRUBY_HANDLER_NONE = 0,
  NGX_HTTP_MRUBY_HANDLER_SET,
  NGX_HTTP_MRUBY_HANDLER_POST_READ,
  NGX_HTTP_MRUBY_HANDLER_SERVER_REWRITE,
  NGX_HTTP_MRUBY_HANDLER_REWRITE,
  NGX_HTTP_MRUBY_HANDLER_ACCESS,
  NGX_HTTP_MRUBY_HANDLER_CONTENT,
  NGX_HTTP_MRUBY_HANDLER_LOG,
  NGX_HTTP_MRUBY_HANDLER_HEADER_FILTER,
  NGX_HTTP_MRUBY_HANDLER_BODY_FILTER
} ngx_http_mruby_handler_kind_t;

typedef struct ngx_http_mruby_ctx_t {
  ngx_mrb_rputs_chain_list_t *rputs_chain;
  u_char *body;
  u_char *last;
  size_t body_length;
  unsigned request_body_more : 1;
  unsigned read_request_body_done : 1;
  ngx_uint_t phase;
  // for response of sub_request using async method
  unsigned sub_response_more : 1;
  u_char *sub_response_body;
  ngx_uint_t sub_response_status;
  size_t sub_response_body_length;
  ngx_http_headers_out_t sub_response_headers;
  mrb_value *async_handler_result;
  ngx_str_t set_var_target;
  mrb_value *fiber_proc;
  // the kind of the handler whose fiber runs now; ngx_mrb_run_fiber sets it
  // for the time a fiber runs
  ngx_http_mruby_handler_kind_t handler_kind;
} ngx_http_mruby_ctx_t;

void ngx_mrb_raise_error(mrb_state *mrb, mrb_value obj, ngx_http_request_t *r);
void ngx_mrb_raise_connection_error(mrb_state *mrb, mrb_value exc, ngx_connection_t *c);
void ngx_mrb_raise_cycle_error(mrb_state *mrb, mrb_value obj, ngx_cycle_t *cycle);
void ngx_mrb_raise_conf_error(mrb_state *mrb, mrb_value obj, ngx_conf_t *cf);

// kind is the handler that ran: a content handler that ends without output
// answers 500 there (see ngx_mrb_content_ends_without_response)
ngx_int_t ngx_mrb_finalize_rputs(ngx_http_request_t *r, ngx_http_mruby_ctx_t *ctx, ngx_http_mruby_handler_kind_t kind);
ngx_int_t ngx_mrb_finalize_body_filter(ngx_http_request_t *r, ngx_http_mruby_ctx_t *ctx);
ngx_http_mruby_ctx_t *ngx_mrb_http_get_module_ctx(mrb_state *mrb, ngx_http_request_t *r);

void ngx_mrb_core_class_init(mrb_state *mrb, struct RClass *class);

#endif // NGX_HTTP_MRUBY_CORE_H
