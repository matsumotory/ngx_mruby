/*
// ngx_http_mruby_module.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_MODULE_H
#define NGX_HTTP_MRUBY_MODULE_H

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifdef NGX_WIN32
#include <io.h>
#endif

#include "ngx_http_mruby_core.h"
#include "ngx_http_mruby_init.h"

#define MODULE_NAME "ngx_mruby"
#define MODULE_VERSION "1.20.1"

#if (nginx_version > 1007999)
#define NGX_USE_MRUBY_UPSTREAM
#endif

typedef enum code_type_t { NGX_MRB_CODE_TYPE_FILE, NGX_MRB_CODE_TYPE_STRING } code_type_t;

typedef struct ngx_mrb_state_t {
  mrb_state *mrb;
  int ai;
} ngx_mrb_state_t;

typedef struct ngx_mrb_code_t {
  union code {
    char *file;
    char *string;
  } code;
  code_type_t code_type;
  int n;
  unsigned int cache;
  struct RProc *proc;
  mrbc_context *ctx;
} ngx_mrb_code_t;

#if defined(NDK) && NDK
typedef struct {
  size_t size;
  ngx_str_t script;
  ngx_mrb_state_t *state;
  ngx_mrb_code_t *code;
} ngx_http_mruby_set_var_data_t;
#include <ndk.h>
#endif

extern ngx_module_t ngx_http_mruby_module;

typedef struct {
  ngx_mrb_state_t *state;
  ngx_mrb_code_t *ssl_client_hello_code;
  ngx_mrb_code_t *ssl_client_hello_inline_code;
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
#if (NGX_HTTP_SSL)
#if OPENSSL_VERSION_NUMBER >= 0x1000205fL
  ngx_connection_t *connection;
#endif
#endif
} ngx_http_mruby_srv_conf_t;

typedef struct ngx_http_mruby_main_conf_t {
  ngx_mrb_state_t *state;
  ngx_mrb_code_t *init_code;
  ngx_mrb_code_t *init_worker_code;
  ngx_mrb_code_t *exit_worker_code;
  ngx_int_t enabled_header_filter;
  ngx_int_t enabled_body_filter;
} ngx_http_mruby_main_conf_t;

typedef struct ngx_http_mruby_loc_conf_t {
  ngx_mrb_state_t *state;
  ngx_mrb_code_t *post_read_code;
  ngx_mrb_code_t *server_rewrite_code;
  ngx_mrb_code_t *rewrite_code;
  ngx_mrb_code_t *access_code;
  ngx_mrb_code_t *content_code;
  ngx_mrb_code_t *log_code;
  ngx_mrb_code_t *post_read_inline_code;
  ngx_mrb_code_t *server_rewrite_inline_code;
  ngx_mrb_code_t *rewrite_inline_code;
  ngx_mrb_code_t *access_inline_code;
  ngx_mrb_code_t *content_inline_code;
  ngx_mrb_code_t *log_inline_code;
  ngx_mrb_code_t *header_filter_code;
  ngx_mrb_code_t *header_filter_inline_code;
  ngx_mrb_code_t *body_filter_code;
  ngx_mrb_code_t *body_filter_inline_code;
  ngx_list_t *set_code_list;
  ngx_flag_t cached;
  ngx_flag_t add_handler;
  ngx_flag_t enable_read_request_body;

  // filter handlers
  ngx_http_handler_pt header_filter_handler;
  ngx_http_output_body_filter_pt body_filter_handler;
} ngx_http_mruby_loc_conf_t;

ngx_http_output_header_filter_pt ngx_http_next_header_filter;
ngx_http_output_body_filter_pt ngx_http_next_body_filter;

#endif // NGX_HTTP_MRUBY_MODULE_H
