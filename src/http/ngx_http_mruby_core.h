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

/*
 * The fixed names that the C code of the http module passes to mruby while
 * it handles a request. mrb_intern_cstr(), and the mrb_funcall() and
 * mrb_class_get() calls that take a name, look the name up in mruby's symbol
 * table on every call: mruby 3.3 searches the preset symbols and then a hash
 * chain; mruby 4.0, until the state has 256 runtime symbols, scans them
 * linearly and calls strlen() on each literal symbol it compares. The request
 * path passes symbols instead (mrb_funcall_id(), mrb_class_get_id(),
 * mrb_const_get(), mrb_iv_get() and mrb_iv_set() take one):
 *
 * - the names that mruby itself defines (to_s, inspect, backtrace, first)
 *   are preset symbols in every build, so the code uses MRB_SYM(), which is
 *   a constant;
 * - the names below are interned once per mrb_state, the first time a call
 *   needs one of them, and NGX_HTTP_MRUBY_SYM(mrb, id) returns the symbol.
 *
 * The names below are not interned when the state is created. A
 * configuration whose requests never reach these calls then has the same
 * symbol ids and the same heap as before. Interning them at creation moved
 * the instructions per request of such configurations by up to 0.6% either
 * way in test/perf, with the same calls: mrb_vm_find_method() and
 * mrb_const_get(), whose work depends on the ids of the symbols they look up
 * in tables keyed by symbol, and malloc(), whose work depends on the free
 * chunks of the heap, did more or less work.
 *
 * The calls still look the class, the constant, the instance variable or the
 * method up on every call, so a script that assigns another value to a
 * constant or redefines a method sees the same behavior as before.
 *
 * X(id, name): NGX_HTTP_MRUBY_SYM(mrb, id) is the symbol of name in mrb.
 */
#define NGX_HTTP_MRUBY_SYM_LIST(X)                                                                                     \
  X(NGINX, "Nginx")                                                                                                    \
  X(VAR, "Var")                                                                                                        \
  X(HEADERS_IN, "Headers_in")                                                                                          \
  X(HEADERS_OUT, "Headers_out")                                                                                        \
  X(ASYNC, "Async")                                                                                                    \
  X(HTTP, "HTTP")                                                                                                      \
  X(RESPONSE, "Response")                                                                                              \
  X(IV_VAR, "@iv_var")                                                                                                 \
  X(HEADERS_IN_OBJ, "headers_in_obj")                                                                                  \
  X(HEADERS_OUT_OBJ, "headers_out_obj")                                                                                \
  X(IV_HEADERS, "@headers")                                                                                            \
  X(IV_STATUS, "@status")                                                                                              \
  X(IV_BODY, "@body")                                                                                                  \
  X(REQUEST_BODY, "request_body")                                                                                      \
  X(HOST, "host")                                                                                                      \
  X(HTTP_HOST, "http_host")                                                                                            \
  X(REQUEST_FILENAME, "request_filename")                                                                              \
  X(REMOTE_USER, "remote_user")                                                                                        \
  X(REMOTE_ADDR, "remote_addr")                                                                                        \
  X(REMOTE_PORT, "remote_port")                                                                                        \
  X(SERVER_ADDR, "server_addr")                                                                                        \
  X(SERVER_PORT, "server_port")                                                                                        \
  X(DOCUMENT_ROOT, "document_root")                                                                                    \
  X(REALPATH_ROOT, "realpath_root")

#define NGX_HTTP_MRUBY_SYM_ENUM(id, name) NGX_HTTP_MRUBY_SYM_##id,
typedef enum { NGX_HTTP_MRUBY_SYM_LIST(NGX_HTTP_MRUBY_SYM_ENUM) NGX_HTTP_MRUBY_SYM_COUNT } ngx_http_mruby_sym_t;
#undef NGX_HTTP_MRUBY_SYM_ENUM

/*
 * The symbols and the mrb_state they belong to. The id of a runtime symbol
 * depends on the order in which a state interned it, so a symbol is valid
 * only in its own state, and a process can hold more than one mrb_state of
 * the http module: a reload creates the state of the new configuration while
 * the old one still exists (with master_process off, the old cycle and its
 * state stay until ngx_clean_old_cycles() destroys them). So
 * ngx_http_mruby_sym() interns the names again when it is called with
 * another state, and ngx_http_mruby_syms_init() makes mrb_close() forget the
 * state, because a new state may get the address of a closed one.
 */
typedef struct {
  mrb_state *mrb;
  mrb_sym sym[NGX_HTTP_MRUBY_SYM_COUNT];
} ngx_http_mruby_syms_t;

extern ngx_http_mruby_syms_t ngx_http_mruby_syms;

void ngx_http_mruby_syms_init(mrb_state *mrb);
void ngx_http_mruby_syms_fill(mrb_state *mrb);

static ngx_inline mrb_sym ngx_http_mruby_sym(mrb_state *mrb, ngx_http_mruby_sym_t id)
{
  if (ngx_http_mruby_syms.mrb != mrb) {
    ngx_http_mruby_syms_fill(mrb);
  }
  return ngx_http_mruby_syms.sym[id];
}

#define NGX_HTTP_MRUBY_SYM(mrb, id) ngx_http_mruby_sym((mrb), NGX_HTTP_MRUBY_SYM_##id)

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
