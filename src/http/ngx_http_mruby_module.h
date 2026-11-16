/*
// ngx_http_mruby_module.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_MODULE_H
#define NGX_HTTP_MRUBY_MODULE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <mruby.h>
#include <mruby/compile.h>

#include "../common/ngx_mruby_code.h"

#define MODULE_NAME "ngx_mruby"
#define MODULE_VERSION "3.0.0"

typedef struct ngx_mrb_state_t {
  mrb_state *mrb;
  int ai;
} ngx_mrb_state_t;

#if defined(NDK) && NDK
typedef struct {
  size_t size;
  ngx_str_t script;
  ngx_mrb_state_t *state;
  ngx_mrb_code_t *code;
  ngx_str_t target;
} ngx_http_mruby_set_var_data_t;
#include <ndk.h>
#endif

extern ngx_module_t ngx_http_mruby_module;

/*
 * The directives with Ruby code that the http module keeps for later, one row
 * per hook or handler kind (section 2.5 of docs/proposals/core-alpha1.md).
 * Each row gives the file and the inline directive of its kind, and
 * ngx_http_mruby_module.c makes from the rows the command entries (the file
 * directive takes the path and "cache", the inline directive the code), and
 * for the handler kinds the fields of the location configuration, their
 * create, merge and cleanup, the phase handlers and their registration. A
 * directive of a new kind is one more row. The kinds of a row:
 *
 * - HOOK(file, inline_, contexts, conf, field): code that runs outside any
 *   request, once (mruby_init) or in each worker (the worker hooks). Both
 *   forms set one field, field (an offsetof) of the configuration conf (an
 *   NGX_HTTP_*_CONF_OFFSET), so that a hook takes one of them.
 * - PHASE(KIND, name, phase, file, inline_, contexts): the handlers of a
 *   phase of a request. Each form has its own field in the location
 *   configuration, code[NGX_HTTP_MRUBY_CODE_KIND][form], and its own handler,
 *   ngx_http_mruby_<name>_handler and ngx_http_mruby_<name>_inline_handler,
 *   which runs the code as NGX_HTTP_MRUBY_HANDLER_KIND. Both handlers are
 *   added to phase, the file handler first, in the order of the rows; the
 *   log phase gets them at its front (ngx_http_mruby_handler_init).
 * - FILTER(KIND, name, file, inline_, contexts): an output filter, with the
 *   fields of a PHASE row and the filter handlers of ngx_http_mruby_module.c
 *   (ngx_http_mruby_<name>_handler and ngx_http_mruby_<name>_inline_handler),
 *   which the directive sets for its location.
 *
 * mruby_set and mruby_set_code (a list of codes per location), the SSL
 * handshake handler (one field per form in the server configuration) and
 * mruby_server_context_handler_code (run while nginx reads the
 * configuration) are written out in ngx_http_mruby_module.c. Every directive
 * with Ruby code sets its field with ngx_mrb_code_set, which refuses a field
 * that is set already.
 */
#define NGX_HTTP_MRUBY_LOC_CONTEXTS (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF)

#define NGX_HTTP_MRUBY_CODE_TABLE(HOOK, PHASE, FILTER)                                                                 \
  HOOK("mruby_init", "mruby_init_code", NGX_HTTP_MAIN_CONF, NGX_HTTP_MAIN_CONF_OFFSET,                                 \
       offsetof(ngx_http_mruby_main_conf_t, init_code))                                                                \
  HOOK("mruby_init_worker", "mruby_init_worker_code", NGX_HTTP_MAIN_CONF, NGX_HTTP_MAIN_CONF_OFFSET,                   \
       offsetof(ngx_http_mruby_main_conf_t, init_worker_code))                                                         \
  HOOK("mruby_exit_worker", "mruby_exit_worker_code", NGX_HTTP_MAIN_CONF, NGX_HTTP_MAIN_CONF_OFFSET,                   \
       offsetof(ngx_http_mruby_main_conf_t, exit_worker_code))                                                         \
  PHASE(POST_READ, post_read, NGX_HTTP_POST_READ_PHASE, "mruby_post_read_handler", "mruby_post_read_handler_code",     \
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF)                                                                        \
  PHASE(SERVER_REWRITE, server_rewrite, NGX_HTTP_SERVER_REWRITE_PHASE, "mruby_server_rewrite_handler",                 \
        "mruby_server_rewrite_handler_code", NGX_HTTP_MRUBY_LOC_CONTEXTS)                                              \
  PHASE(REWRITE, rewrite, NGX_HTTP_REWRITE_PHASE, "mruby_rewrite_handler", "mruby_rewrite_handler_code",               \
        NGX_HTTP_MRUBY_LOC_CONTEXTS)                                                                                   \
  PHASE(ACCESS, access, NGX_HTTP_ACCESS_PHASE, "mruby_access_handler", "mruby_access_handler_code",                    \
        NGX_HTTP_MRUBY_LOC_CONTEXTS)                                                                                   \
  PHASE(CONTENT, content, NGX_HTTP_CONTENT_PHASE, "mruby_content_handler", "mruby_content_handler_code",               \
        NGX_HTTP_MRUBY_LOC_CONTEXTS)                                                                                   \
  PHASE(LOG, log, NGX_HTTP_LOG_PHASE, "mruby_log_handler", "mruby_log_handler_code", NGX_HTTP_MRUBY_LOC_CONTEXTS)      \
  FILTER(HEADER_FILTER, header_filter, "mruby_output_header_filter", "mruby_output_header_filter_code",                \
         NGX_HTTP_MRUBY_LOC_CONTEXTS)                                                                                  \
  FILTER(BODY_FILTER, body_filter, "mruby_output_body_filter", "mruby_output_body_filter_code",                        \
         NGX_HTTP_MRUBY_LOC_CONTEXTS)

#define NGX_HTTP_MRUBY_TABLE_SKIP(...)
#define NGX_HTTP_MRUBY_CODE_INDEX(KIND, name, ...) NGX_HTTP_MRUBY_CODE_##KIND,

// The handler kinds of the table (its PHASE and FILTER rows), which index
// code of the location configuration and uses of the main configuration.
typedef enum {
  NGX_HTTP_MRUBY_CODE_TABLE(NGX_HTTP_MRUBY_TABLE_SKIP, NGX_HTTP_MRUBY_CODE_INDEX, NGX_HTTP_MRUBY_CODE_INDEX)
      NGX_HTTP_MRUBY_CODES
} ngx_http_mruby_code_index_t;

typedef struct {
  ngx_mrb_state_t *state;
  ngx_mrb_code_t *ssl_handshake_code;
  ngx_mrb_code_t *ssl_handshake_inline_code;
  ngx_mrb_code_t *server_config_inline_code;
  ngx_conf_t *cf;
  ngx_http_core_srv_conf_t *cscf;
  ngx_str_t *servername;
  ngx_str_t cert_path;
  ngx_str_t cert_key_path;
  ngx_str_t cert_data;
  ngx_str_t cert_key_data;
#if (NGX_HTTP_SSL) && OPENSSL_VERSION_NUMBER >= 0x1000205fL
  ngx_connection_t *connection;
#endif
} ngx_http_mruby_srv_conf_t;

typedef struct ngx_http_mruby_main_conf_t {
  ngx_mrb_state_t *state;
  ngx_mrb_code_t *init_code;
  ngx_mrb_code_t *init_worker_code;
  ngx_mrb_code_t *exit_worker_code;
  /*
   * Which handler kinds and forms the directives of the configuration use,
   * anywhere: uses[kind][form] is 1 once a directive of that kind and form
   * has set its code (ngx_http_mruby_handler_directive). Postconfiguration
   * adds the output filters only when one is used (ngx_http_mruby_init).
   */
  ngx_flag_t uses[NGX_HTTP_MRUBY_CODES][NGX_MRB_CODE_FORMS];
  /*
   * For the accessors that Nginx::Var#method_missing defines (see
   * ngx_mrb_var_define_accessor in ngx_http_mruby_var.c). They belong to the
   * mrb_state of this configuration, not to C static variables: a reload
   * creates the state of the new configuration while the old one can still
   * exist. Each worker has its own copy after the fork.
   * - var_class: Nginx::Var of the state. It is only compared with the class
   *   of a receiver, so a script that removes the constant leaves no
   *   pointer that is used.
   * - var_prefix_accessors: how many accessors of prefix variables (arg_,
   *   http_, ...) the worker has defined, at most
   *   NGX_HTTP_MRUBY_VAR_PREFIX_ACCESSORS_MAX.
   */
  struct RClass *var_class;
  ngx_uint_t var_prefix_accessors;
  /*
   * The declarations of mruby_variable (pointers to the
   * ngx_http_mruby_variable_t of ngx_http_mruby_var.c), or NULL when there
   * is none. Read while nginx reads the configuration only.
   */
  ngx_array_t *variables;
} ngx_http_mruby_main_conf_t;

#define NGX_HTTP_MRUBY_VAR_PREFIX_ACCESSORS_MAX 16

typedef struct ngx_http_mruby_loc_conf_t {
  ngx_mrb_state_t *state;
  // the code of each handler kind of NGX_HTTP_MRUBY_CODE_TABLE and form, or
  // NGX_CONF_UNSET_PTR
  ngx_mrb_code_t *code[NGX_HTTP_MRUBY_CODES][NGX_MRB_CODE_FORMS];
  ngx_list_t *set_code_list;
  ngx_flag_t cached;
  ngx_flag_t add_handler;
  ngx_flag_t enable_read_request_body;

  // filter handlers
  ngx_http_handler_pt header_filter_handler;
  ngx_http_output_body_filter_pt body_filter_handler;
} ngx_http_mruby_loc_conf_t;

extern ngx_http_output_header_filter_pt ngx_http_next_header_filter;
extern ngx_http_output_body_filter_pt ngx_http_next_body_filter;

#endif // NGX_HTTP_MRUBY_MODULE_H
