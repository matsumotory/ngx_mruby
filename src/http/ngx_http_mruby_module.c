/*
** ngx_mruby - A Web Server Extension Mechanism Using mruby
**
** See Copyright Notice in LEGAL
*/

#include "ngx_http_mruby_module.h"

#include "ngx_http_mruby_async.h"
#include "ngx_http_mruby_core.h"
#include "ngx_http_mruby_init.h"
#include "ngx_http_mruby_request.h"

#include <mruby/presym.h>
#include <mruby/proc.h>
#include <mruby/string.h>

#define ON 1
#define OFF 0

#define NGX_MRUBY_MERGE_CODE(conf_code, prev_code)                                                                     \
  if (conf_code == NGX_CONF_UNSET_PTR) {                                                                               \
    conf_code = prev_code;                                                                                             \
  }

#define NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mrb, code)                                                                    \
  if (code != NGX_CONF_UNSET_PTR && mrb && (code)->ctx) {                                                              \
    mrbc_context_free(mrb, (code)->ctx);                                                                               \
    (code)->ctx = NULL;                                                                                                \
  }

ngx_http_output_header_filter_pt ngx_http_next_header_filter;
ngx_http_output_body_filter_pt ngx_http_next_body_filter;

// set conf
static void *ngx_http_mruby_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_mruby_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static void *ngx_http_mruby_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_mruby_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_mruby_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_mruby_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

// set init function
static ngx_int_t ngx_http_mruby_preinit(ngx_conf_t *cf);
static ngx_int_t ngx_http_mruby_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_mruby_handler_init(ngx_http_core_main_conf_t *cmcf);
static ngx_int_t ngx_http_mruby_init_worker(ngx_cycle_t *cycle);
static void ngx_http_mruby_exit_worker(ngx_cycle_t *cycle);

/*
// ngx_mruby mruby core functions
*/
static ngx_int_t ngx_mrb_run(ngx_http_request_t *r, ngx_mrb_state_t *state, ngx_mrb_code_t *code, ngx_flag_t cached,
                             ngx_str_t *result, ngx_http_mruby_handler_kind_t kind);
static ngx_int_t ngx_mrb_run_request(ngx_http_request_t *r, ngx_mrb_state_t *state, ngx_mrb_code_t *code,
                                     ngx_flag_t cached, ngx_str_t *result, ngx_http_mruby_handler_kind_t kind);
static ngx_int_t ngx_mrb_run_cycle(ngx_cycle_t *cycle, ngx_mrb_state_t *state, ngx_mrb_code_t *code);
static ngx_int_t ngx_mrb_run_conf(ngx_conf_t *cf, ngx_mrb_state_t *state, ngx_mrb_code_t *code);

/*
// ngx_mruby mruby state functions
*/

static ngx_int_t ngx_http_mruby_state_reinit_from_file(ngx_mrb_state_t *state, ngx_mrb_code_t *code);
static ngx_mrb_code_t *ngx_http_mruby_mrb_code_from_file(ngx_pool_t *pool, ngx_str_t *code_file_path);
static ngx_mrb_code_t *ngx_http_mruby_mrb_code_from_string(ngx_pool_t *pool, ngx_str_t *code_s);
static ngx_int_t ngx_http_mruby_shared_state_init(ngx_conf_t *cf, ngx_mrb_state_t *state);
static ngx_int_t ngx_http_mruby_shared_state_compile(ngx_conf_t *cf, ngx_mrb_state_t *state, ngx_mrb_code_t *code);

/*
// ngx_mruby mruby directive functions
*/

static char *ngx_http_mruby_init_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_init_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_init_worker_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_init_worker_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_exit_worker_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_exit_worker_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
#if (NGX_HTTP_SSL)
static char *ngx_http_mruby_ssl_handshake_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_ssl_handshake_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
#endif /* NGX_HTTP_SSL */
static char *ngx_http_mruby_server_config_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_mruby_post_read_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_server_rewrite_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_rewrite_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_access_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_content_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_log_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_post_read_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_server_rewrite_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_rewrite_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_access_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_content_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_log_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_body_filter_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_body_filter_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_header_filter_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_header_filter_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* output directive error */
static char *ngx_http_mruby_output_filter_error(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#if defined(NDK) && NDK
static char *ngx_http_mruby_set_inner(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, code_type_t type);
static char *ngx_http_mruby_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_set_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
#endif

/* helpers */
static char *ngx_http_mruby_initialize_inline_code(ngx_conf_t *cf, ngx_mrb_state_t *state, ngx_mrb_code_t **code,
                                                   const char *func_name);
static char *ngx_http_mruby_initialize_code(ngx_conf_t *cf, ngx_mrb_state_t *state, ngx_mrb_code_t **code,
                                            const char *func_name);

/*
// ngx_mruby mruby handler functions
*/
static ngx_int_t ngx_http_mruby_post_read_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_mruby_server_rewrite_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_mruby_rewrite_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_mruby_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_mruby_content_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_mruby_log_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_mruby_post_read_inline_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_mruby_server_rewrite_inline_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_mruby_rewrite_inline_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_mruby_access_inline_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_mruby_content_inline_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_mruby_log_inline_handler(ngx_http_request_t *r);

#if (NGX_HTTP_SSL)
#if OPENSSL_VERSION_NUMBER >= 0x1000205fL
static int ngx_http_mruby_ssl_cert_handler(ngx_ssl_conn_t *ssl_conn, void *data);
#endif
#endif /* NGX_HTTP_SSL */

#if defined(NDK) && NDK
static ngx_int_t ngx_http_mruby_set_handler(ngx_http_request_t *r, ngx_str_t *val, ngx_http_variable_value_t *v,
                                            void *data);
static ngx_int_t ngx_http_mruby_set_inline_handler(ngx_http_request_t *r, ngx_str_t *val, ngx_http_variable_value_t *v,
                                                   void *data);
#endif

/*
// ngx_mruby mruby filter functions
*/
static ngx_int_t ngx_http_mruby_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_mruby_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_mruby_read_body(ngx_http_request_t *r, ngx_chain_t *in, ngx_http_mruby_ctx_t *ctx);
static void ngx_http_mruby_header_filter_init(void);
static void ngx_http_mruby_body_filter_init(void);
static ngx_int_t ngx_http_mruby_body_filter_handler_inner(ngx_http_request_t *r, ngx_chain_t *in, code_type_t type);
static ngx_int_t ngx_http_mruby_body_filter_handler(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_mruby_body_filter_inline_handler(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_mruby_header_filter_handler(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_mruby_header_filter_inline_handler(ngx_http_request_t *r, ngx_chain_t *in);

static ngx_command_t ngx_http_mruby_commands[] = {

    {ngx_string("mruby_server_context_handler_code"), NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_mruby_server_config_inline, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL},

#if (NGX_HTTP_SSL)

    /* server config */
    {ngx_string("mruby_ssl_handshake_handler"), NGX_HTTP_SRV_CONF | NGX_CONF_TAKE12, ngx_http_mruby_ssl_handshake_phase,
     NGX_HTTP_SRV_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_ssl_handshake_handler_code"), NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_mruby_ssl_handshake_inline, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL},

#endif /* NGX_HTTP_SSL */

    /* main config */
    {ngx_string("mruby_init_code"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ngx_http_mruby_init_inline,
     NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_init"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE12, ngx_http_mruby_init_phase,
     NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_init_worker_code"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ngx_http_mruby_init_worker_inline,
     NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_init_worker"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE12, ngx_http_mruby_init_worker_phase,
     NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_exit_worker_code"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ngx_http_mruby_exit_worker_inline,
     NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_exit_worker"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE12, ngx_http_mruby_exit_worker_phase,
     NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_cache"), NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http_mruby_loc_conf_t, cached), NULL},

    {ngx_string("mruby_add_handler"), NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http_mruby_loc_conf_t, add_handler), NULL},

    {ngx_string("mruby_enable_read_request_body"), NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http_mruby_loc_conf_t, enable_read_request_body),
     NULL},

    {ngx_string("mruby_post_read_handler"), NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE12,
     ngx_http_mruby_post_read_phase, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_server_rewrite_handler"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE12,
     ngx_http_mruby_server_rewrite_phase, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_rewrite_handler"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE12,
     ngx_http_mruby_rewrite_phase, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_access_handler"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE12,
     ngx_http_mruby_access_phase, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_content_handler"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE12,
     ngx_http_mruby_content_phase, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_log_handler"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE12,
     ngx_http_mruby_log_phase, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_post_read_handler_code"), NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_mruby_post_read_inline, NGX_HTTP_LOC_CONF_OFFSET, 0, ngx_http_mruby_post_read_inline_handler},

    {ngx_string("mruby_server_rewrite_handler_code"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
     ngx_http_mruby_server_rewrite_inline, NGX_HTTP_LOC_CONF_OFFSET, 0, ngx_http_mruby_server_rewrite_inline_handler},

    {ngx_string("mruby_rewrite_handler_code"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
     ngx_http_mruby_rewrite_inline, NGX_HTTP_LOC_CONF_OFFSET, 0, ngx_http_mruby_rewrite_inline_handler},

    {ngx_string("mruby_access_handler_code"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
     ngx_http_mruby_access_inline, NGX_HTTP_LOC_CONF_OFFSET, 0, ngx_http_mruby_access_inline_handler},

    {ngx_string("mruby_content_handler_code"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
     ngx_http_mruby_content_inline, NGX_HTTP_LOC_CONF_OFFSET, 0, ngx_http_mruby_content_inline_handler},

    {ngx_string("mruby_log_handler_code"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
     ngx_http_mruby_log_inline, NGX_HTTP_LOC_CONF_OFFSET, 0, ngx_http_mruby_log_inline_handler},

#if defined(NDK) && NDK
    {ngx_string("mruby_set"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_2MORE,
     ngx_http_mruby_set, NGX_HTTP_LOC_CONF_OFFSET, 0, ngx_http_mruby_set_handler},

    {ngx_string("mruby_set_code"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_2MORE,
     ngx_http_mruby_set_inline, NGX_HTTP_LOC_CONF_OFFSET, 0, ngx_http_mruby_set_inline_handler},
#endif

    {ngx_string("mruby_output_filter"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE12,
     ngx_http_mruby_output_filter_error, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_output_filter_code"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE12,
     ngx_http_mruby_output_filter_error, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_output_body_filter"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE12,
     ngx_http_mruby_body_filter_phase, NGX_HTTP_LOC_CONF_OFFSET, 0, ngx_http_mruby_body_filter_handler},

    {ngx_string("mruby_output_body_filter_code"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
     ngx_http_mruby_body_filter_inline, NGX_HTTP_LOC_CONF_OFFSET, 0, ngx_http_mruby_body_filter_inline_handler},

    {ngx_string("mruby_output_header_filter"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE12,
     ngx_http_mruby_header_filter_phase, NGX_HTTP_LOC_CONF_OFFSET, 0, ngx_http_mruby_header_filter_handler},

    {ngx_string("mruby_output_header_filter_code"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
     ngx_http_mruby_header_filter_inline, NGX_HTTP_LOC_CONF_OFFSET, 0, ngx_http_mruby_header_filter_inline_handler},

    ngx_null_command};

static ngx_http_module_t ngx_http_mruby_module_ctx = {
    ngx_http_mruby_preinit, /* preconfiguration */
    ngx_http_mruby_init,    /* postconfiguration */

    ngx_http_mruby_create_main_conf, /* create main configuration */
    ngx_http_mruby_init_main_conf,   /* init main configuration */

    ngx_http_mruby_create_srv_conf, /* create server configuration */
    ngx_http_mruby_merge_srv_conf,  /* merge server configuration */

    ngx_http_mruby_create_loc_conf, /* create location configuration */
    ngx_http_mruby_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_mruby_module = {NGX_MODULE_V1,
                                      &ngx_http_mruby_module_ctx, /* module context */
                                      ngx_http_mruby_commands,    /* module directives */
                                      NGX_HTTP_MODULE,            /* module type */
                                      NULL,                       /* init master */
                                      NULL,                       /* init module */
                                      ngx_http_mruby_init_worker, /* init process */
                                      NULL,                       /* init thread */
                                      NULL,                       /* exit thread */
                                      ngx_http_mruby_exit_worker, /* exit process */
                                      NULL,                       /* exit master */
                                      NGX_MODULE_V1_PADDING};

static void ngx_http_mruby_main_conf_cleanup(void *data)
{
  ngx_http_mruby_main_conf_t *mmcf = data;

  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mmcf->state->mrb, mmcf->init_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mmcf->state->mrb, mmcf->init_worker_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mmcf->state->mrb, mmcf->exit_worker_code);

  mrb_close(mmcf->state->mrb);
}

static void *ngx_http_mruby_create_main_conf(ngx_conf_t *cf)
{
  ngx_int_t rc;
  ngx_http_mruby_main_conf_t *mmcf;
  ngx_pool_cleanup_t *cln;

  cln = ngx_pool_cleanup_add(cf->pool, 0);
  if (cln == NULL) {
    return NULL;
  }
  mmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mruby_main_conf_t));
  if (mmcf == NULL) {
    return NULL;
  }
  mmcf->state = ngx_pcalloc(cf->pool, sizeof(ngx_mrb_state_t));
  if (mmcf->state == NULL) {
    return NULL;
  }

  mmcf->init_code = NGX_CONF_UNSET_PTR;
  mmcf->init_worker_code = NGX_CONF_UNSET_PTR;
  mmcf->exit_worker_code = NGX_CONF_UNSET_PTR;

  rc = ngx_http_mruby_shared_state_init(cf, mmcf->state);
  if (rc == NGX_ERROR) {
    return NULL;
  }

  cln->handler = ngx_http_mruby_main_conf_cleanup;
  cln->data = mmcf;

  return mmcf;
}

static char *ngx_http_mruby_init_main_conf(ngx_conf_t *cf, void *conf)
{
  return NGX_CONF_OK;
}

/* create server config phase */

static void ngx_http_mruby_srv_conf_cleanup(void *data)
{
  ngx_http_mruby_srv_conf_t *mscf = data;

  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mscf->state->mrb, mscf->ssl_handshake_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mscf->state->mrb, mscf->ssl_handshake_inline_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mscf->state->mrb, mscf->server_config_inline_code);
}

static void *ngx_http_mruby_create_srv_conf(ngx_conf_t *cf)
{
  ngx_http_mruby_srv_conf_t *mscf;
  ngx_pool_cleanup_t *cln;

  mscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mruby_srv_conf_t));
  if (mscf == NULL) {
    return NULL;
  }

  mscf->state = ngx_pcalloc(cf->pool, sizeof(ngx_mrb_state_t));
  if (mscf->state == NULL) {
    return NULL;
  }

  cln = ngx_pool_cleanup_add(cf->pool, 0);
  if (cln == NULL) {
    return NULL;
  }

  mscf->cert_path.len = 0;
  mscf->cert_key_path.len = 0;
  mscf->cert_data.len = 0;
  mscf->cert_key_data.len = 0;
  mscf->ssl_handshake_code = NGX_CONF_UNSET_PTR;
  mscf->ssl_handshake_inline_code = NGX_CONF_UNSET_PTR;
  mscf->server_config_inline_code = NGX_CONF_UNSET_PTR;

  cln->handler = ngx_http_mruby_srv_conf_cleanup;
  cln->data = mscf;

  return mscf;
}

static char *ngx_http_mruby_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{

  ngx_http_mruby_srv_conf_t *prev = parent;
  ngx_http_mruby_srv_conf_t *conf = child;

#if (NGX_HTTP_SSL)
  ngx_http_ssl_srv_conf_t *sscf;

  NGX_MRUBY_MERGE_CODE(conf->ssl_handshake_code, prev->ssl_handshake_code);
  NGX_MRUBY_MERGE_CODE(conf->ssl_handshake_inline_code, prev->ssl_handshake_inline_code);

  if (conf->ssl_handshake_code != NGX_CONF_UNSET_PTR || conf->ssl_handshake_inline_code != NGX_CONF_UNSET_PTR) {
    sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
    if (sscf == NULL || sscf->ssl.ctx == NULL) {
      ngx_log_error(NGX_LOG_EMERG, cf->log, 0, MODULE_NAME " : no ssl configured for the server");
      return NGX_CONF_ERROR;
    }

#if OPENSSL_VERSION_NUMBER >= 0x1000205fL
    SSL_CTX_set_cert_cb(sscf->ssl.ctx, ngx_http_mruby_ssl_cert_handler, NULL);
#else
    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                  MODULE_NAME
                  " : mruby_ssl_handshake_handler : OpenSSL 1.0.2e or later required but found " OPENSSL_VERSION_TEXT);
    return NGX_CONF_ERROR;
#endif
  }

#endif /* NGX_HTTP_SSL */

  NGX_MRUBY_MERGE_CODE(conf->server_config_inline_code, prev->server_config_inline_code);

  return NGX_CONF_OK;
}

/* create location config phase */

static void ngx_http_mruby_loc_conf_cleanup(void *data)
{
  ngx_http_mruby_loc_conf_t *conf = data;
  ngx_list_part_t *part;
  ngx_mrb_code_t **code;
  ngx_uint_t i;

  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(conf->state->mrb, conf->post_read_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(conf->state->mrb, conf->server_rewrite_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(conf->state->mrb, conf->rewrite_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(conf->state->mrb, conf->access_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(conf->state->mrb, conf->content_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(conf->state->mrb, conf->log_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(conf->state->mrb, conf->post_read_inline_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(conf->state->mrb, conf->server_rewrite_inline_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(conf->state->mrb, conf->rewrite_inline_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(conf->state->mrb, conf->access_inline_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(conf->state->mrb, conf->content_inline_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(conf->state->mrb, conf->log_inline_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(conf->state->mrb, conf->body_filter_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(conf->state->mrb, conf->body_filter_inline_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(conf->state->mrb, conf->header_filter_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(conf->state->mrb, conf->header_filter_inline_code);

  part = &conf->set_code_list->part;
  code = part->elts;
  for (i = 0;; i++) {
    if (i >= part->nelts) {
      if (part->next == NULL) {
        break;
      }
      part = part->next;
      code = part->elts;
      i = 0;
    }
    NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(conf->state->mrb, *code);
  }
}

static void *ngx_http_mruby_create_loc_conf(ngx_conf_t *cf)
{
  ngx_http_mruby_loc_conf_t *conf;
  ngx_pool_cleanup_t *cln;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mruby_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }
  conf->state = ngx_pcalloc(cf->pool, sizeof(ngx_mrb_state_t));
  if (conf->state == NULL) {
    return NULL;
  }
  conf->set_code_list = ngx_list_create(cf->pool, 1, sizeof(ngx_mrb_code_t *));
  cln = ngx_pool_cleanup_add(cf->pool, 0);
  if (cln == NULL) {
    return NULL;
  }

  conf->post_read_code = NGX_CONF_UNSET_PTR;
  conf->server_rewrite_code = NGX_CONF_UNSET_PTR;
  conf->rewrite_code = NGX_CONF_UNSET_PTR;
  conf->access_code = NGX_CONF_UNSET_PTR;
  conf->content_code = NGX_CONF_UNSET_PTR;
  conf->log_code = NGX_CONF_UNSET_PTR;

  conf->post_read_inline_code = NGX_CONF_UNSET_PTR;
  conf->server_rewrite_inline_code = NGX_CONF_UNSET_PTR;
  conf->rewrite_inline_code = NGX_CONF_UNSET_PTR;
  conf->access_inline_code = NGX_CONF_UNSET_PTR;
  conf->content_inline_code = NGX_CONF_UNSET_PTR;
  conf->log_inline_code = NGX_CONF_UNSET_PTR;

  conf->body_filter_code = NGX_CONF_UNSET_PTR;
  conf->body_filter_inline_code = NGX_CONF_UNSET_PTR;
  conf->header_filter_code = NGX_CONF_UNSET_PTR;
  conf->header_filter_inline_code = NGX_CONF_UNSET_PTR;

  conf->cached = NGX_CONF_UNSET;
  conf->add_handler = NGX_CONF_UNSET;
  conf->enable_read_request_body = NGX_CONF_UNSET;

  cln->handler = ngx_http_mruby_loc_conf_cleanup;
  cln->data = conf;

  return conf;
}

static char *ngx_http_mruby_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_mruby_loc_conf_t *prev = parent;
  ngx_http_mruby_loc_conf_t *conf = child;

  NGX_MRUBY_MERGE_CODE(conf->post_read_code, prev->post_read_code);
  NGX_MRUBY_MERGE_CODE(conf->server_rewrite_code, prev->server_rewrite_code);
  NGX_MRUBY_MERGE_CODE(conf->rewrite_code, prev->rewrite_code);
  NGX_MRUBY_MERGE_CODE(conf->access_code, prev->access_code);
  NGX_MRUBY_MERGE_CODE(conf->content_code, prev->content_code);
  NGX_MRUBY_MERGE_CODE(conf->log_code, prev->log_code);

  NGX_MRUBY_MERGE_CODE(conf->post_read_inline_code, prev->post_read_inline_code);
  NGX_MRUBY_MERGE_CODE(conf->server_rewrite_inline_code, prev->server_rewrite_inline_code);
  NGX_MRUBY_MERGE_CODE(conf->rewrite_inline_code, prev->rewrite_inline_code);
  NGX_MRUBY_MERGE_CODE(conf->access_inline_code, prev->access_inline_code);
  NGX_MRUBY_MERGE_CODE(conf->content_inline_code, prev->content_inline_code);
  NGX_MRUBY_MERGE_CODE(conf->log_inline_code, prev->log_inline_code);

  NGX_MRUBY_MERGE_CODE(conf->body_filter_code, prev->body_filter_code);
  NGX_MRUBY_MERGE_CODE(conf->body_filter_inline_code, prev->body_filter_inline_code);
  NGX_MRUBY_MERGE_CODE(conf->header_filter_code, prev->header_filter_code);
  NGX_MRUBY_MERGE_CODE(conf->header_filter_inline_code, prev->header_filter_inline_code);

  ngx_conf_merge_value(conf->cached, prev->cached, 0);
  ngx_conf_merge_value(conf->add_handler, prev->add_handler, 0);
  ngx_conf_merge_value(conf->enable_read_request_body, prev->enable_read_request_body, 0);

  return NGX_CONF_OK;
}

static ngx_int_t ngx_http_mruby_preinit(ngx_conf_t *cf)
{
  /* callback after creating main conf */
  return NGX_OK;
}

static ngx_int_t ngx_http_mruby_init(ngx_conf_t *cf)
{
  ngx_http_core_main_conf_t *cmcf;
  ngx_http_mruby_main_conf_t *mmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);

  /* nginx reads the configuration through its startup log, which logs at
     notice whatever error_log says (issue #320), so this goes at info. */
  ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "%s/%s (%s/%s) mechanism enabled", MODULE_NAME, MODULE_VERSION,
                     MRUBY_RUBY_ENGINE, MRUBY_VERSION);

  if (ngx_http_mruby_handler_init(cmcf) != NGX_OK) {
    return NGX_ERROR;
  }

  if (mmcf->enabled_header_filter) {
    ngx_http_mruby_header_filter_init();
  }
  if (mmcf->enabled_body_filter) {
    ngx_http_mruby_body_filter_init();
  }

  if (mmcf->init_code != NGX_CONF_UNSET_PTR) {
    return ngx_mrb_run_conf(cf, mmcf->state, mmcf->init_code);
  }

  return NGX_OK;
}

static ngx_int_t ngx_http_mruby_init_worker(ngx_cycle_t *cycle)
{
  ngx_http_mruby_main_conf_t *mmcf;

  mmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_mruby_module);

  /* the configuration has no http {} block */
  if (mmcf == NULL) {
    return NGX_OK;
  }

  if (mmcf->init_worker_code != NGX_CONF_UNSET_PTR) {
    return ngx_mrb_run_cycle(cycle, mmcf->state, mmcf->init_worker_code);
  }

  return NGX_OK;
}

static void ngx_http_mruby_exit_worker(ngx_cycle_t *cycle)
{
  ngx_http_mruby_main_conf_t *mmcf;

  mmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_mruby_module);

  /* the configuration has no http {} block */
  if (mmcf == NULL) {
    return;
  }

  if (mmcf->exit_worker_code != NGX_CONF_UNSET_PTR) {
    ngx_mrb_run_cycle(cycle, mmcf->state, mmcf->exit_worker_code);
  }
}

static ngx_int_t ngx_http_mruby_handler_init(ngx_http_core_main_conf_t *cmcf)
{
  ngx_int_t i;
  ngx_http_handler_pt *h;
  ngx_http_phases phase;
  ngx_http_phases phases[] = {
      NGX_HTTP_POST_READ_PHASE,
      // NGX_HTTP_FIND_CONFIG_PHASE,
      NGX_HTTP_SERVER_REWRITE_PHASE,
      NGX_HTTP_REWRITE_PHASE,
      // NGX_HTTP_POST_REWRITE_PHASE,
      // NGX_HTTP_PREACCESS_PHASE,
      NGX_HTTP_ACCESS_PHASE,
      // NGX_HTTP_POST_ACCESS_PHASE,
      // NGX_HTTP_TRY_FILES_PHASE,
      NGX_HTTP_CONTENT_PHASE,
      NGX_HTTP_LOG_PHASE,
  };
  ngx_int_t phases_c;

  phases_c = sizeof(phases) / sizeof(ngx_http_phases);
  for (i = 0; i < phases_c; i++) {
    phase = phases[i];
    h = ngx_array_push(&cmcf->phases[phase].handlers);
    if (h == NULL) {
      return NGX_ERROR;
    }
    switch (phase) {
    case NGX_HTTP_POST_READ_PHASE:
      *h = ngx_http_mruby_post_read_handler;
      h = ngx_array_push(&cmcf->phases[phase].handlers);
      if (h == NULL) {
        return NGX_ERROR;
      }
      *h = ngx_http_mruby_post_read_inline_handler;
      break;
    case NGX_HTTP_SERVER_REWRITE_PHASE:
      *h = ngx_http_mruby_server_rewrite_handler;
      h = ngx_array_push(&cmcf->phases[phase].handlers);
      if (h == NULL) {
        return NGX_ERROR;
      }
      *h = ngx_http_mruby_server_rewrite_inline_handler;
      break;
    case NGX_HTTP_REWRITE_PHASE:
      *h = ngx_http_mruby_rewrite_handler;
      h = ngx_array_push(&cmcf->phases[phase].handlers);
      if (h == NULL) {
        return NGX_ERROR;
      }
      *h = ngx_http_mruby_rewrite_inline_handler;
      break;
    case NGX_HTTP_ACCESS_PHASE:
      *h = ngx_http_mruby_access_handler;
      h = ngx_array_push(&cmcf->phases[phase].handlers);
      if (h == NULL) {
        return NGX_ERROR;
      }
      *h = ngx_http_mruby_access_inline_handler;
      break;
    case NGX_HTTP_CONTENT_PHASE:
      *h = ngx_http_mruby_content_handler;
      h = ngx_array_push(&cmcf->phases[phase].handlers);
      if (h == NULL) {
        return NGX_ERROR;
      }
      *h = ngx_http_mruby_content_inline_handler;
      break;
    case NGX_HTTP_LOG_PHASE:
      *h = ngx_http_mruby_log_handler;
      h = ngx_array_push(&cmcf->phases[phase].handlers);
      if (h == NULL) {
        return NGX_ERROR;
      }
      *h = ngx_http_mruby_log_inline_handler;
      break;
    default:
      // not through
      break;
    }
  }

  return NGX_OK;
}

/*
// ngx_mruby mruby core functions
*/

static void ngx_mrb_state_clean(ngx_http_request_t *r, ngx_mrb_state_t *state)
{
  state->mrb->exc = 0;
}

static void ngx_mrb_code_clean(ngx_http_request_t *r, ngx_mrb_state_t *state, ngx_mrb_code_t *code)
{
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(state->mrb, code);
}

ngx_int_t ngx_mrb_run_cycle(ngx_cycle_t *cycle, ngx_mrb_state_t *state, ngx_mrb_code_t *code)
{
  int ai = mrb_gc_arena_save(state->mrb);
  ngx_http_request_t *prev_r;
  ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "%s INFO %s:%d: mrb_run", MODULE_NAME, __func__, __LINE__);

  /* init_worker and exit_worker code runs outside of any request */
  prev_r = ngx_mrb_get_request();
  ngx_mrb_push_request(NULL);
  mrb_toplevel_run(state->mrb, code->proc);
  ngx_mrb_push_request(prev_r);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(state->mrb, code);
  if (state->mrb->exc) {
    ngx_mrb_raise_cycle_error(state->mrb, mrb_obj_value(state->mrb->exc), cycle);
    mrb_gc_arena_restore(state->mrb, ai);
    return NGX_ERROR;
  }

  mrb_gc_arena_restore(state->mrb, ai);
  return NGX_OK;
}

ngx_int_t ngx_mrb_run_conf(ngx_conf_t *cf, ngx_mrb_state_t *state, ngx_mrb_code_t *code)
{
  int ai = mrb_gc_arena_save(state->mrb);
  ngx_log_error(NGX_LOG_INFO, cf->log, 0, "%s INFO %s:%d: mrb_run", MODULE_NAME, __func__, __LINE__);
  mrb_toplevel_run(state->mrb, code->proc);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(state->mrb, code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(state->mrb, code);
  if (state->mrb->exc) {
    ngx_mrb_raise_conf_error(state->mrb, mrb_obj_value(state->mrb->exc), cf);
    mrb_gc_arena_restore(state->mrb, ai);
    return NGX_ERROR;
  }

  mrb_gc_arena_restore(state->mrb, ai);
  return NGX_OK;
}

/*
 * Request-scoped Ruby methods find their request through a process-wide
 * pointer. Set it only while the code runs and restore the previous value
 * afterwards, so that it never points to a finished request. Restoring
 * (rather than clearing) keeps it valid when a handler runs nested, for
 * example through an internal redirect from Ruby code.
 */
ngx_int_t ngx_mrb_run(ngx_http_request_t *r, ngx_mrb_state_t *state, ngx_mrb_code_t *code, ngx_flag_t cached,
                      ngx_str_t *result, ngx_http_mruby_handler_kind_t kind)
{
  ngx_int_t rc;
  ngx_http_request_t *prev_r;

  prev_r = ngx_mrb_get_request();
  ngx_mrb_push_request(r);
  rc = ngx_mrb_run_request(r, state, code, cached, result, kind);
  ngx_mrb_push_request(prev_r);

  return rc;
}

/*
 * Whether a handler of this kind can wait for the rest of the request body.
 * nginx's checkers of these phases wait when the handler returns NGX_DONE,
 * and ngx_http_mruby_read_request_body_cb runs the phases again, so the
 * handler runs once more with the body (see ngx_mrb_run_request). mruby_set
 * handlers run inside NDK's rewrite script, log handlers inside
 * ngx_http_free_request, and filters inside ngx_http_send_header and
 * ngx_http_output_filter; all of them go on as soon as the handler returns.
 */
static ngx_flag_t ngx_mrb_handler_waits_for_request_body(ngx_http_mruby_handler_kind_t kind)
{
  switch (kind) {
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

// The name of a handler that cannot wait for the request body, for messages.
static const char *ngx_mrb_request_body_kind_name(ngx_http_mruby_handler_kind_t kind)
{
  switch (kind) {
  case NGX_HTTP_MRUBY_HANDLER_SET:
    return "an mruby_set handler";
  case NGX_HTTP_MRUBY_HANDLER_LOG:
    return "a log handler";
  case NGX_HTTP_MRUBY_HANDLER_HEADER_FILTER:
    return "a header filter";
  case NGX_HTTP_MRUBY_HANDLER_BODY_FILTER:
    return "a body filter";
  default:
    return "this handler";
  }
}

/*
 * Whether ngx_http_read_client_request_body would call its post handler
 * before it returns, so that no read stays running after the call. These are
 * its paths that complete at once: a subrequest; a body that was already
 * read, is being read or was discarded; a request without a body; and an
 * HTTP/1.x body with Content-Length that is entirely in the buffer that
 * nginx read the request headers into. A chunked body and every HTTP/2 or
 * HTTP/3 body count as not complete: nginx reads those through events. A
 * body that a waiting handler of ngx_mruby is still reading is checked with
 * request_body_more in ngx_mrb_run_request: nginx would call the post handler
 * at once for it too, but the body is not complete.
 */
static ngx_flag_t ngx_http_mruby_request_body_complete(ngx_http_request_t *r)
{
  if (r != r->main || r->request_body != NULL || r->discard_body) {
    return 1;
  }

#if defined(nginx_version) && nginx_version >= 1003009
  if (r->headers_in.chunked) {
    return 0;
  }
#endif

  if (r->headers_in.content_length_n < 0) {
    return 1;
  }

#ifdef NGX_HTTP_VERSION_20
  if (r->http_version >= NGX_HTTP_VERSION_20) {
    return 0;
  }
#endif

  if (r->header_in == NULL) {
    return 0;
  }

  return r->headers_in.content_length_n <= (off_t)(r->header_in->last - r->header_in->pos);
}

void ngx_http_mruby_read_request_body_cb(ngx_http_request_t *r)
{
  ngx_http_mruby_ctx_t *ctx = ngx_mrb_http_get_module_ctx(NULL, r);

  // The reference to the request that ngx_http_read_client_request_body
  // took is dropped by ngx_mrb_run_request, not here (see there).
  if (ctx != NULL) {
    ctx->read_request_body_done = 1;

    if (ctx->request_body_more) {
      ctx->request_body_more = 0;
      // ngx_http_read_client_request_body set the write event handler to
      // ngx_http_request_empty_handler while it read the body. Restore the
      // one of the phases before running them again, as nginx's mirror
      // module does, so that a later phase handler that waits, such as
      // auth_request for its subrequest, is resumed through it.
      r->write_event_handler = ngx_http_core_run_phases;
      ngx_http_core_run_phases(r);
    }
  }
}

// kind is the kind of handler that calls ngx_mrb_run; it decides whether
// Nginx::Async may suspend the fiber (see ngx_http_mruby_handler_kind_t).
static ngx_int_t ngx_mrb_run_request(ngx_http_request_t *r, ngx_mrb_state_t *state, ngx_mrb_code_t *code,
                                     ngx_flag_t cached, ngx_str_t *result, ngx_http_mruby_handler_kind_t kind)
{
  int result_len;
  int ai = 0;
  ngx_flag_t raised = 0;
  ngx_mrb_rputs_chain_list_t *rputs_chain;
  ngx_chain_t **rputs_last;
  off_t content_length_n;
  mrb_value *mrb_result = (mrb_value *)ngx_palloc(r->pool, sizeof(mrb_value));
  *mrb_result = mrb_nil_value();
  ngx_http_mruby_ctx_t *ctx;
  ngx_http_mruby_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);

  if (state == NGX_CONF_UNSET_PTR || code == NGX_CONF_UNSET_PTR) {
    return NGX_DECLINED;
  }

  ctx = ngx_mrb_http_get_module_ctx(NULL, r);
  if (ctx == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory context %s:%d", __FUNCTION__,
                  __LINE__);
    return NGX_ERROR;
  }

  // ngx_mrb_post_fiber assigns the result of a resumed fiber to
  // ctx->set_var_target. Only the mruby_set handlers pass a result and set
  // the target before they run, so every other handler clears it.
  if (result == NULL) {
    ngx_str_null(&ctx->set_var_target);
  }

  /* force reading body */
  if (mlcf->enable_read_request_body && !ctx->read_request_body_done && !ngx_mrb_handler_waits_for_request_body(kind) &&
      (ctx->request_body_more || !ngx_http_mruby_request_body_complete(r))) {
    /*
     * A handler that cannot wait reads the body only when the read completes
     * at once. A read that waited would keep its reference to the request
     * after the handler returned, and its callback would run the phases
     * again from wherever the request is then. The handler runs without the
     * body instead; a later handler that can wait, or a module such as
     * proxy_pass, still reads the whole body.
     *
     * request_body_more is set while the read of a waiting handler has not
     * completed. r->request_body is set then, so nginx would call the
     * callback at once, and the callback would run the phases again for the
     * waiting handler from inside this one. That happens when nginx ends the
     * read without the rest of the body and goes on with the request: a log
     * handler after the client closed the connection or client_body_timeout
     * expired, a filter while nginx sends its 400 or 413 page for the body.
     * Such a body is not complete either.
     */
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "%s INFO %s:%d: mrb_run: the request body is not complete and %s cannot wait for it, so it runs "
                  "without the body",
                  MODULE_NAME, __func__, __LINE__, ngx_mrb_request_body_kind_name(kind));
  } else if (mlcf->enable_read_request_body && !ctx->read_request_body_done) {
    ngx_int_t rc;

    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;

    rc = ngx_http_read_client_request_body(r, ngx_http_mruby_read_request_body_cb);

    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "%s INFO %s:%d: mrb_run: tried to read request body, but got %d.", MODULE_NAME, __func__, __LINE__,
                    rc);
#if (nginx_version < 1002006) || (nginx_version >= 1003000 && nginx_version < 1003009)
      r->main->count--;
#endif
      return rc;
    }

    if (rc == NGX_AGAIN) {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "%s INFO %s:%d: mrb_run: tried to read request body, but got NGX_AGAIN.", MODULE_NAME, __func__,
                    __LINE__);
      ctx->read_request_body_done = 0;

      /*
       * ngx_http_mruby_read_request_body_cb runs the phases again once the
       * rest of the body is read. A phase handler tells nginx to wait for
       * that with NGX_DONE. The rewrite phase checker (server_rewrite and
       * rewrite handlers) and the content phase checker pass NGX_AGAIN to
       * ngx_http_finalize_request, which ends the request: it sets the read
       * handler to ngx_http_block_reading, so the body was not read further
       * and the handler did not run again. The post_read and access checkers
       * treat NGX_AGAIN and NGX_DONE alike.
       *
       * The reference to the request that ngx_http_read_client_request_body
       * took is dropped at once, as nginx's mirror module does with
       * ngx_http_finalize_request(r, NGX_DONE); the read handler that nginx
       * installed keeps the request until the body is read, the client
       * closes the connection or client_body_timeout expires. For the
       * content handler the content phase checker makes that call itself
       * with the NGX_DONE it gets.
       */
      switch (kind) {
      case NGX_HTTP_MRUBY_HANDLER_POST_READ:
      case NGX_HTTP_MRUBY_HANDLER_SERVER_REWRITE:
      case NGX_HTTP_MRUBY_HANDLER_REWRITE:
      case NGX_HTTP_MRUBY_HANDLER_ACCESS:
        ctx->request_body_more = 1;
        ngx_http_finalize_request(r, NGX_DONE);
        return NGX_DONE;
      case NGX_HTTP_MRUBY_HANDLER_CONTENT:
        ctx->request_body_more = 1;
        return NGX_DONE;
      default:
        /*
         * Not reached with nginx's own request body filters: a handler that
         * cannot wait gets here only when ngx_http_mruby_request_body_complete
         * said the read completes at once. If a third-party body filter
         * still makes it wait, the reference is dropped here as well, and
         * request_body_more stays 0, so the callback does not run the phases
         * again. A log handler runs when the request count is already 0, so
         * the count is decremented directly instead of through
         * ngx_http_finalize_request.
         */
#if defined(nginx_version) && nginx_version >= 8011
        r->main->count--;
#endif
        return NGX_AGAIN;
      }
    }

#if defined(nginx_version) && nginx_version >= 8011
    // The read completed at once and ngx_http_read_client_request_body has
    // called the callback already. Drop the reference that it took; a log
    // handler runs when the count is already 0, so this is not done through
    // ngx_http_finalize_request either.
    r->main->count--;
#endif
  }

  ai = mrb_gc_arena_save(state->mrb);
  if (!cached && !code->cache && code->code_type == NGX_MRB_CODE_TYPE_FILE) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s INFO %s:%d: mrb_run info: ai=%d", MODULE_NAME, __func__,
                  __LINE__, ai);
    ngx_int_t rc;
    rc = ngx_http_mruby_state_reinit_from_file(state, code);
    if (rc != NGX_OK) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, MODULE_NAME " : mrb_run: failed to recompile %s, rc=%d",
                    code->code.file, rc);
      mrb_gc_arena_restore(state->mrb, ai);
      return rc;
    }
  }

  ctx->sub_response_more = 0;

  // The chain of Nginx.rputs and the length of the response before the code
  // runs, for an exception in a header filter (see below).
  rputs_chain = ctx->rputs_chain;
  rputs_last = rputs_chain != NULL ? rputs_chain->last : NULL;
  content_length_n = r->headers_out.content_length_n;

  if (mrb_test(ngx_mrb_start_fiber(r, state->mrb, code->proc, mrb_result, kind))) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s INFO %s:%d: already can resume this fiber", MODULE_NAME,
                  __func__, __LINE__);

    mrb_gc_arena_restore(state->mrb, ai);

    // waiting sub request response
    if (ctx->sub_response_more) {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s INFO %s:%d: more sub request processing", MODULE_NAME,
                    __func__, __LINE__);
      return NGX_AGAIN;
    }

    return NGX_DONE;
  } else {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s INFO %s:%d: already finish this fiber, can not resume",
                  MODULE_NAME, __func__, __LINE__);
  }

  if (state->mrb->exc) {
    raised = 1;
    ngx_mrb_raise_error(state->mrb, mrb_obj_value(state->mrb->exc), r);
    r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    // drop the output of Nginx.rputs: with it, ngx_mrb_finalize_rputs would
    // send that output as a 200 response; without it, the function returns
    // the 500, as ngx_mrb_post_fiber does after an exception in a resumed
    // fiber. Nginx.rputs also added the length of that output to
    // content_length_n: put back the value from before the first string of
    // the chain, because after an mruby_set handler or a filter the request
    // goes on and its response must not count the dropped output.
    // A header filter runs inside ngx_http_send_header. A chain that already
    // existed when the filter started is an earlier handler's: the handler
    // that started the response calls ngx_http_send_header from
    // ngx_mrb_finalize_rputs and sends that chain after the header through
    // its own pointer. Only the strings that the header filter added are
    // taken out of it, and the length gets back the value it had when the
    // filter started, which counts the earlier output.
    if (ctx->rputs_chain != NULL) {
      if (kind == NGX_HTTP_MRUBY_HANDLER_HEADER_FILTER && ctx->rputs_chain == rputs_chain) {
        (*rputs_last)->next = NULL;
        rputs_chain->last = rputs_last;
        r->headers_out.content_length_n = content_length_n;
      } else {
        r->headers_out.content_length_n = ctx->rputs_chain->content_length_n;
      }
      ctx->rputs_chain = NULL;
    }
    mrb_gc_arena_restore(state->mrb, ai);
  } else if (result != NULL) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s INFO %s:%d: fiber done in request phase", MODULE_NAME,
                  __func__, __LINE__);
    if (mrb_nil_p(*mrb_result)) {
      result->data = NULL;
      result->len = 0;
    } else {
      if (mrb_type(*mrb_result) != MRB_TT_STRING) {
        *mrb_result = mrb_funcall_id(state->mrb, *mrb_result, MRB_SYM_2(state->mrb, to_s), 0);
      }
      result_len = RSTRING_LEN(*mrb_result);
      result->data = ngx_palloc(r->pool, result_len);
      if (result->data == NULL) {
        if (!cached && !code->cache) {
          ngx_mrb_code_clean(r, state, code);
        }
        return NGX_ERROR;
      }
      ngx_memcpy(result->data, RSTRING_PTR(*mrb_result), RSTRING_LEN(*mrb_result));
      result->len = result_len;
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s INFO %s:%d: mrb_run info: return value=(%*s)", MODULE_NAME,
                    __func__, __LINE__, result->len, result->data);
      mrb_gc_arena_restore(state->mrb, ai);
      if (!cached && !code->cache) {
        ngx_mrb_code_clean(r, state, code);
      }
      return NGX_OK;
    }
  }
  mrb_gc_arena_restore(state->mrb, ai);
  if (!cached && !code->cache) {
    ngx_mrb_code_clean(r, state, code);
  }
  ngx_mrb_state_clean(r, state);

  // Only the mruby_set handlers pass a result. After an exception the
  // variable gets an empty string, as for a handler that returns nil. NDK has
  // no case for the 500 that ngx_mrb_finalize_rputs returns, so nginx stored
  // whatever value was on its script stack in the variable; NGX_DECLINED
  // would do the same, because ngx_http_script_set_var_code takes the length
  // and the data of that value and marks the variable as found.
  if (raised && result != NULL) {
    result->data = NULL;
    result->len = 0;
    return NGX_OK;
  }

  // A filter runs while nginx sends a response (#206).
  // - A header filter runs inside ngx_http_send_header, so it returns here
  //   without ngx_mrb_finalize_rputs, which would call ngx_http_send_header
  //   and so run the header filter again, without end. An rputs chain stays
  //   in the module ctx. When the handler that started the response wrote
  //   it, that handler sends it after the header. When the header filter
  //   wrote it, which is not supported, the body that nginx sends does not
  //   contain it, although Nginx.rputs added its length to Content-Length.
  //   The next handler that finalizes, such as a log handler, sends the
  //   chain after the response, and nginx logs "header already sent".
  // - A body filter that runs after a header filter sent the header, or in a
  //   location with an mruby header filter, which holds the header back
  //   until the body filter has run (ngx_http_mruby_header_filter_send),
  //   does not call ngx_mrb_finalize_rputs either. With an rputs chain, that
  //   function would call ngx_http_send_header once more, which only logs
  //   "header already sent" when the header is out, or runs the code of the
  //   header filter a second time when it is held back, and would set the
  //   status to 200. The body filter drops the module ctx where that
  //   function dropped it: when there is an rputs chain and the status is 200
  //   or the last buffer of the chain is not marked as the last one. A chain
  //   left in the ctx there would be sent after the response by the next
  //   handler that finalizes, such as a log handler.
  //   ngx_mrb_finalize_body_filter and a handler that is sending its own
  //   chain through this filter keep their own pointers to the ctx and the
  //   chain.
  //   Otherwise the ctx stays, as it did. That is the case after Nginx.rputs
  //   and then Nginx.return, Nginx.status_code= or Nginx.send_header with
  //   another status, when nginx sends the response for that status, such
  //   as its error page. ngx_mrb_finalize_body_filter marks the ctx so that
  //   this filter passes on the calls that ngx_http_writer makes when the
  //   response needs more than one write, and the next handler that
  //   finalizes only returns the status.
  // - A body filter without a header filter still calls
  //   ngx_mrb_finalize_rputs: the mruby header filter has held the header
  //   back, so nothing is sent, and running that filter again keeps the
  //   length of the body filter's output once the body filter holds a body,
  //   which test/t/cases/filter_connection.rb pins.
  if (kind == NGX_HTTP_MRUBY_HANDLER_HEADER_FILTER) {
    return NGX_OK;
  }

  if (kind == NGX_HTTP_MRUBY_HANDLER_BODY_FILTER && (r->header_sent || mlcf->header_filter_handler != NULL)) {
    if (ctx->rputs_chain != NULL &&
        (r->headers_out.status == NGX_HTTP_OK || !(*ctx->rputs_chain->last)->buf->last_buf)) {
      ngx_http_set_ctx(r, NULL, ngx_http_mruby_module);
    }
    return NGX_OK;
  }

  if (ngx_http_get_module_ctx(r, ngx_http_mruby_module) != NULL) {
    return ngx_mrb_finalize_rputs(r, ctx, kind);
  }

  return NGX_OK;
}

/*
// ngx_mruby mruby state functions
*/

static ngx_int_t ngx_http_mruby_state_reinit_from_file(ngx_mrb_state_t *state, ngx_mrb_code_t *code)
{
  FILE *mrb_file;
  mrb_value proc;

  if ((mrb_file = fopen((char *)code->code.file, "r")) == NULL) {
    return NGX_ERROR;
  }

  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(state->mrb, code);
  code->ctx = mrbc_context_new(state->mrb);
  mrbc_filename(state->mrb, code->ctx, (char *)code->code.file);
  code->ctx->no_exec = TRUE;
  proc = mrb_load_file_cxt(state->mrb, mrb_file, code->ctx);
  fclose(mrb_file);

  if (!mrb_proc_p(proc)) {
    return NGX_ERROR;
  }

  code->proc = mrb_proc_ptr(proc);

  return NGX_OK;
}

static ngx_mrb_code_t *ngx_http_mruby_mrb_code_from_file(ngx_pool_t *pool, ngx_str_t *code_file_path)
{
  ngx_mrb_code_t *code;
  size_t len;

  code = ngx_pcalloc(pool, sizeof(*code));
  if (code == NULL) {
    return NGX_CONF_UNSET_PTR;
  }

  len = code_file_path->len;
  code->code.file = ngx_palloc(pool, len + 1);
  if (code->code.file == NULL) {
    return NGX_CONF_UNSET_PTR;
  }
  ngx_cpystrn((u_char *)code->code.file, (u_char *)code_file_path->data, code_file_path->len + 1);
  code->code_type = NGX_MRB_CODE_TYPE_FILE;
  code->cache = OFF;
  return code;
}

static ngx_mrb_code_t *ngx_http_mruby_mrb_code_from_string(ngx_pool_t *pool, ngx_str_t *code_s)
{
  ngx_mrb_code_t *code;
  size_t len;

  code = ngx_pcalloc(pool, sizeof(*code));
  if (code == NULL) {
    return NGX_CONF_UNSET_PTR;
  }
  len = code_s->len;
  code->code.string = ngx_palloc(pool, len + 1);
  if (code->code.string == NULL) {
    return NGX_CONF_UNSET_PTR;
  }
  ngx_cpystrn((u_char *)code->code.string, code_s->data, len + 1);
  code->code_type = NGX_MRB_CODE_TYPE_STRING;
  code->cache = ON;
  return code;
}

static ngx_int_t ngx_http_mruby_shared_state_init(ngx_conf_t *cf, ngx_mrb_state_t *state)
{
  mrb_state *mrb;

  mrb = mrb_open();
  if (mrb == NULL) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s: mrb_open() failed", MODULE_NAME);
    return NGX_ERROR;
  }
  /* mruby 4.x returns the state with mrb->exc set, instead of NULL, when the
     initialization of the core or of an mrbgem raised. What comes after the
     raise is not initialized, so the state is not used. */
  if (mrb->exc != NULL) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s: mrb_open() failed: %s raised while initializing mruby", MODULE_NAME,
                       mrb_obj_classname(mrb, mrb_obj_value(mrb->exc)));
    mrb_close(mrb);
    return NGX_ERROR;
  }
  ngx_http_mruby_syms_init(mrb);
  ngx_mrb_class_init(mrb);

  state->mrb = mrb;

  return NGX_OK;
}

static ngx_int_t ngx_http_mruby_shared_state_compile(ngx_conf_t *cf, ngx_mrb_state_t *state, ngx_mrb_code_t *code)
{
  FILE *mrb_file;
  mrb_value proc;

  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(state->mrb, code);
  code->ctx = mrbc_context_new(state->mrb);
  code->ctx->no_exec = TRUE;
#ifdef NGX_MRUBY_IREP_DEBUG
  code->ctx->dump_result = TRUE;
#endif

  if (code->code_type == NGX_MRB_CODE_TYPE_FILE) {
    if ((mrb_file = fopen((char *)code->code.file, "r")) == NULL) {
      return NGX_ERROR;
    }
    mrbc_filename(state->mrb, code->ctx, (char *)code->code.file);
    proc = mrb_load_file_cxt(state->mrb, mrb_file, code->ctx);
    fclose(mrb_file);
  } else {
    mrbc_filename(state->mrb, code->ctx, "INLINE CODE");
    proc = mrb_load_string_cxt(state->mrb, (char *)code->code.string, code->ctx);
  }

  if (!mrb_proc_p(proc)) {
    return NGX_ERROR;
  }

  code->proc = mrb_proc_ptr(proc);
#ifdef NGX_MRUBY_IREP_DEBUG
  /* mrb_codedump_all() is not declared in mruby headers. So just follows the mruby way. See mruby/src/load.c. */
  void mrb_codedump_all(mrb_state *, struct RProc *);
  mrb_codedump_all(state->mrb, code->proc);
#endif

  /* A debugging aid for each directive, logged while nginx reads the
     configuration through its startup log, which error_log cannot filter. */
  if (code->code_type == NGX_MRB_CODE_TYPE_FILE) {
    ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "%s INFO %s:%d: compile info: code->code.file=(%s) code->cache=(%d)",
                       MODULE_NAME, __func__, __LINE__, code->code.file, code->cache);
  } else {
    ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
                       "%s INFO %s:%d: compile info: "
                       "code->code.string=(%s) code->cache=(%d)",
                       MODULE_NAME, __func__, __LINE__, code->code.string, code->cache);
  }

  return NGX_OK;
}

/*
// ngx_mruby mruby directive functions
*/

/* helpers */
static char *ngx_http_mruby_initialize_inline_code(ngx_conf_t *cf, ngx_mrb_state_t *state, ngx_mrb_code_t **code,
                                                   const char *func_name)
{
  ngx_str_t *value;
  ngx_int_t rc;

  if (*code != NGX_CONF_UNSET_PTR) {
    return "is duplicated";
  }

  value = cf->args->elts;
  *code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
  if (*code == NGX_CONF_UNSET_PTR) {
    return NGX_CONF_ERROR;
  }
  rc = ngx_http_mruby_shared_state_compile(cf, state, *code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, MODULE_NAME " : %s mrb_string(%s) load failed", func_name, value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_initialize_code(ngx_conf_t *cf, ngx_mrb_state_t *state, ngx_mrb_code_t **code,
                                            const char *func_name)
{
  ngx_str_t *value;
  ngx_int_t rc;

  if (*code != NGX_CONF_UNSET_PTR) {
    return "is duplicated";
  }

  value = cf->args->elts;
  *code = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
  if (*code == NGX_CONF_UNSET_PTR) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, MODULE_NAME " : %s mrb_file(%s) open failed", func_name, value[1].data);
    return NGX_CONF_ERROR;
  }
  if (cf->args->nelts == 3) {
    if (ngx_strcmp(value[2].data, "cache") == 0) {
      (*code)->cache = ON;
    } else {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\", valid parameter is only \"cache\"",
                         &value[2]);
      return NGX_CONF_ERROR;
    }
  }
  rc = ngx_http_mruby_shared_state_compile(cf, state, *code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, MODULE_NAME " : %s mrb_file(%s) open failed", func_name, value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_server_config_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_srv_conf_t *mscf = (ngx_http_mruby_srv_conf_t *)conf;
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  char *rc;

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mscf->state = mmcf->state;

  rc = ngx_http_mruby_initialize_inline_code(cf, mmcf->state, &mscf->server_config_inline_code, __func__);
  if (rc != NGX_CONF_OK) {
    return rc;
  }

  if (mscf->server_config_inline_code != NGX_CONF_UNSET_PTR) {
    ngx_int_t ret;
    void *prev_ud;
    mscf->cf = cf;
    mscf->cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);
    prev_ud = mmcf->state->mrb->ud;
    mmcf->state->mrb->ud = mscf;
    ret = ngx_mrb_run_conf(cf, mmcf->state, mscf->server_config_inline_code);
    /* cf lives only while the configuration is parsed (see ngx_mrb_add_listener()) */
    mmcf->state->mrb->ud = prev_ud;
    mscf->cf = NULL;
    mscf->cscf = NULL;
    if (ret != NGX_OK) {
      return NGX_CONF_ERROR;
    }
  }

  return NGX_CONF_OK;
}

#if (NGX_HTTP_SSL)

static char *ngx_http_mruby_ssl_handshake_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_srv_conf_t *mscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mscf->state = mmcf->state;

  return ngx_http_mruby_initialize_code(cf, mscf->state, &mscf->ssl_handshake_code, __func__);
}

static char *ngx_http_mruby_ssl_handshake_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_srv_conf_t *mscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mscf->state = mmcf->state;

  return ngx_http_mruby_initialize_inline_code(cf, mmcf->state, &mscf->ssl_handshake_inline_code, __func__);
}
#endif /* NGX_HTTP_SSL */

static char *ngx_http_mruby_init_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);

  return ngx_http_mruby_initialize_code(cf, mmcf->state, &mmcf->init_code, __func__);
}

static char *ngx_http_mruby_init_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);

  return ngx_http_mruby_initialize_inline_code(cf, mmcf->state, &mmcf->init_code, __func__);
}

static char *ngx_http_mruby_init_worker_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);

  return ngx_http_mruby_initialize_code(cf, mmcf->state, &mmcf->init_worker_code, __func__);
}

static char *ngx_http_mruby_init_worker_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);

  return ngx_http_mruby_initialize_inline_code(cf, mmcf->state, &mmcf->init_worker_code, __func__);
}

static char *ngx_http_mruby_exit_worker_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);

  return ngx_http_mruby_initialize_code(cf, mmcf->state, &mmcf->exit_worker_code, __func__);
}

static char *ngx_http_mruby_exit_worker_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);

  return ngx_http_mruby_initialize_inline_code(cf, mmcf->state, &mmcf->exit_worker_code, __func__);
}

static char *ngx_http_mruby_output_filter_error(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                     "mruby_output_filter{,_code} was deleted from v1.17.2, you should use "
                     "mruby_output_body_filter{,_code} for response body, or use "
                     "mruby_output_header_filter{,_code} for response headers.");
  return NGX_CONF_ERROR;
}

static char *ngx_http_mruby_post_read_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = conf;

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mlcf->state = mmcf->state;

  return ngx_http_mruby_initialize_code(cf, mlcf->state, &mlcf->post_read_code, __func__);
}

static char *ngx_http_mruby_server_rewrite_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = conf;

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mlcf->state = mmcf->state;

  return ngx_http_mruby_initialize_code(cf, mlcf->state, &mlcf->server_rewrite_code, __func__);
}

static char *ngx_http_mruby_rewrite_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = conf;

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mlcf->state = mmcf->state;

  return ngx_http_mruby_initialize_code(cf, mlcf->state, &mlcf->rewrite_code, __func__);
}

static char *ngx_http_mruby_access_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = conf;

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mlcf->state = mmcf->state;

  return ngx_http_mruby_initialize_code(cf, mlcf->state, &mlcf->access_code, __func__);
}

static char *ngx_http_mruby_content_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = conf;

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mlcf->state = mmcf->state;

  return ngx_http_mruby_initialize_code(cf, mlcf->state, &mlcf->content_code, __func__);
}

static char *ngx_http_mruby_log_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = conf;

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mlcf->state = mmcf->state;

  return ngx_http_mruby_initialize_code(cf, mlcf->state, &mlcf->log_code, __func__);
}

static char *ngx_http_mruby_post_read_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = conf;

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mlcf->state = mmcf->state;

  return ngx_http_mruby_initialize_inline_code(cf, mmcf->state, &mlcf->post_read_inline_code, __func__);
}

static char *ngx_http_mruby_server_rewrite_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = conf;

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mlcf->state = mmcf->state;

  return ngx_http_mruby_initialize_inline_code(cf, mmcf->state, &mlcf->server_rewrite_inline_code, __func__);
}

static char *ngx_http_mruby_rewrite_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = conf;

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mlcf->state = mmcf->state;

  return ngx_http_mruby_initialize_inline_code(cf, mmcf->state, &mlcf->rewrite_inline_code, __func__);
}

static char *ngx_http_mruby_access_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = conf;

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mlcf->state = mmcf->state;

  return ngx_http_mruby_initialize_inline_code(cf, mmcf->state, &mlcf->access_inline_code, __func__);
}

static char *ngx_http_mruby_content_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = conf;

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mlcf->state = mmcf->state;

  return ngx_http_mruby_initialize_inline_code(cf, mmcf->state, &mlcf->content_inline_code, __func__);
}

static char *ngx_http_mruby_log_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = conf;

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mlcf->state = mmcf->state;

  return ngx_http_mruby_initialize_inline_code(cf, mmcf->state, &mlcf->log_inline_code, __func__);
}

static char *ngx_http_mruby_body_filter_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  char *rc;

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mlcf->state = mmcf->state;

  rc = ngx_http_mruby_initialize_code(cf, mlcf->state, &mlcf->body_filter_code, __func__);
  if (rc != NGX_CONF_OK) {
    return rc;
  }
  mmcf->enabled_body_filter = 1;
  mmcf->enabled_header_filter = 1;
  mlcf->body_filter_handler = cmd->post;

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_header_filter_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  char *rc;

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mlcf->state = mmcf->state;

  rc = ngx_http_mruby_initialize_code(cf, mlcf->state, &mlcf->header_filter_code, __func__);
  if (rc != NGX_CONF_OK) {
    return rc;
  }
  mmcf->enabled_header_filter = 1;
  mlcf->header_filter_handler = cmd->post;

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_body_filter_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  char *rc;

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mlcf->state = mmcf->state;

  rc = ngx_http_mruby_initialize_inline_code(cf, mmcf->state, &mlcf->body_filter_inline_code, __func__);
  if (rc != NGX_CONF_OK) {
    return rc;
  }
  mmcf->enabled_body_filter = 1;
  mmcf->enabled_header_filter = 1;
  mlcf->body_filter_handler = cmd->post;

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_header_filter_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  char *rc;

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mlcf->state = mmcf->state;

  rc = ngx_http_mruby_initialize_inline_code(cf, mmcf->state, &mlcf->header_filter_inline_code, __func__);
  if (rc != NGX_CONF_OK) {
    return rc;
  }
  mmcf->enabled_header_filter = 1;
  mlcf->header_filter_handler = cmd->post;

  return NGX_CONF_OK;
}

#if defined(NDK) && NDK
static char *ngx_http_mruby_set_inner(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, code_type_t type)
{
  ngx_str_t *value;
  ndk_set_var_t filter;
  ngx_http_mruby_set_var_data_t *filter_data;
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  ngx_int_t rc;
  ngx_mrb_code_t **code;

  /* mmcf->state is initialized in ngx_http_mruby_preinit() */
  mlcf->state = mmcf->state;

  value = cf->args->elts;

  filter.type = NDK_SET_VAR_MULTI_VALUE_DATA;
  filter.func = cmd->post;
  filter.size = cf->args->nelts - 3;

  filter_data = ngx_pcalloc(cf->pool, sizeof(ngx_http_mruby_set_var_data_t));
  if (filter_data == NULL) {
    return NGX_CONF_ERROR;
  }

  filter_data->target = value[1];
  filter_data->state = mmcf->state;
  filter_data->size = filter.size;
  filter_data->script = value[2];
  if (type == NGX_MRB_CODE_TYPE_FILE) {
    filter_data->code = ngx_http_mruby_mrb_code_from_file(cf->pool, &filter_data->script);
    if (filter_data->code == NGX_CONF_UNSET_PTR) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%V) open failed", &value[2]);
      return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 4) {
      if (ngx_strcmp(value[3].data, "cache") == 0) {
        filter_data->code->cache = ON;
      } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\", valid parameter is only \"cache\"",
                           &value[3]);
        return NGX_CONF_ERROR;
      }
    }
  } else {
    filter_data->code = ngx_http_mruby_mrb_code_from_string(cf->pool, &filter_data->script);
  }

  rc = ngx_http_mruby_shared_state_compile(cf, filter_data->state, filter_data->code);
  if (rc != NGX_OK) {
    if (type == NGX_MRB_CODE_TYPE_FILE) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[2].data);
    } else {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[2].data);
    }
    return NGX_CONF_ERROR;
  }
  if (filter_data->code == NGX_CONF_UNSET_PTR) {
    if (type == NGX_MRB_CODE_TYPE_FILE) {
      ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "failed to load mruby script: %s %s:%d", filter_data->script.data,
                         __FUNCTION__, __LINE__, filter_data->target.data, filter_data->script.data);
    }
    return NGX_CONF_ERROR;
  }

  code = ngx_list_push(mlcf->set_code_list);
  *code = filter_data->code;
  filter.data = filter_data;
  ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "%s INFO %s:%d: target variable=(%s)", MODULE_NAME, __FUNCTION__, __LINE__,
                     filter_data->target.data);

  return ndk_set_var_multi_value_core(cf, &filter_data->target, &value[3], &filter);
}

static char *ngx_http_mruby_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  return ngx_http_mruby_set_inner(cf, cmd, conf, NGX_MRB_CODE_TYPE_FILE);
}

static char *ngx_http_mruby_set_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  return ngx_http_mruby_set_inner(cf, cmd, conf, NGX_MRB_CODE_TYPE_STRING);
}
#endif

/*
// ngx_mruby mruby handler functions
*/

#define NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(handler_name, _code, _kind)                                                \
  static ngx_int_t ngx_http_mruby_##handler_name##_handler(ngx_http_request_t *r)                                      \
  {                                                                                                                    \
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);                        \
    ngx_http_mruby_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);                          \
    if (mmcf->state == NGX_CONF_UNSET_PTR) {                                                                           \
      return NGX_DECLINED;                                                                                             \
    }                                                                                                                  \
    if (_code == NGX_CONF_UNSET_PTR) {                                                                                 \
      return NGX_DECLINED;                                                                                             \
    }                                                                                                                  \
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "hooked mruby file-based " #handler_name " code: %s",           \
                  _code->code.file);                                                                                   \
    return ngx_mrb_run(r, mmcf->state, _code, mlcf->cached, NULL, _kind);                                              \
  }

NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(post_read, mlcf->post_read_code, NGX_HTTP_MRUBY_HANDLER_POST_READ)
NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(server_rewrite, mlcf->server_rewrite_code, NGX_HTTP_MRUBY_HANDLER_SERVER_REWRITE)
NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(rewrite, mlcf->rewrite_code, NGX_HTTP_MRUBY_HANDLER_REWRITE)
NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(access, mlcf->access_code, NGX_HTTP_MRUBY_HANDLER_ACCESS)
NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(log, mlcf->log_code, NGX_HTTP_MRUBY_HANDLER_LOG)

static ngx_int_t ngx_http_mruby_content_handler(ngx_http_request_t *r)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);

  ngx_mrb_code_t *code;
  size_t root;
  ngx_str_t path;

  if (mlcf->add_handler) {
    if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d request_file(%s) map failed", __FUNCTION__, __LINE__,
                    path.data);
      return NGX_ERROR;
    }
    if (access((const char *)path.data, F_OK) != 0) {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s:%d request_file(%s) not found", __FUNCTION__, __LINE__,
                    path.data);
      return NGX_HTTP_NOT_FOUND;
    }
    code = ngx_http_mruby_mrb_code_from_file(r->pool, &path);
    if (code == NGX_CONF_UNSET_PTR) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d mrb_file(%s) open failed", __FUNCTION__, __LINE__,
                    path.data);
      return NGX_ERROR;
    }
  } else {
    code = mlcf->content_code;
  }
  if (code == NGX_CONF_UNSET_PTR) {
    return NGX_DECLINED;
  }
  ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "hooked mruby file-based content code: %s", code->code.file);
  return ngx_mrb_run(r, mmcf->state, code, mlcf->cached, NULL, NGX_HTTP_MRUBY_HANDLER_CONTENT);
}

#define NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(handler_name, _code, _kind)                                         \
  static ngx_int_t ngx_http_mruby_##handler_name##_inline_handler(ngx_http_request_t *r)                               \
  {                                                                                                                    \
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);                        \
    ngx_http_mruby_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);                          \
    if (mmcf->state == NGX_CONF_UNSET_PTR) {                                                                           \
      return NGX_DECLINED;                                                                                             \
    }                                                                                                                  \
    if (_code == NGX_CONF_UNSET_PTR) {                                                                                 \
      return NGX_DECLINED;                                                                                             \
    }                                                                                                                  \
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "hooked mruby inline " #handler_name " code: %s",               \
                  _code->code.string);                                                                                 \
    return ngx_mrb_run(r, mmcf->state, _code, 1, NULL, _kind);                                                         \
  }

NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(post_read, mlcf->post_read_inline_code, NGX_HTTP_MRUBY_HANDLER_POST_READ)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(server_rewrite, mlcf->server_rewrite_inline_code,
                                           NGX_HTTP_MRUBY_HANDLER_SERVER_REWRITE)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(rewrite, mlcf->rewrite_inline_code, NGX_HTTP_MRUBY_HANDLER_REWRITE)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(access, mlcf->access_inline_code, NGX_HTTP_MRUBY_HANDLER_ACCESS)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(content, mlcf->content_inline_code, NGX_HTTP_MRUBY_HANDLER_CONTENT)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(log, mlcf->log_inline_code, NGX_HTTP_MRUBY_HANDLER_LOG)

#if defined(NDK) && NDK
static ngx_int_t ngx_http_mruby_set_handler(ngx_http_request_t *r, ngx_str_t *val, ngx_http_variable_value_t *v,
                                            void *data)
{
  ngx_http_mruby_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
  ngx_http_mruby_set_var_data_t *filter_data;

  filter_data = data;

  ngx_http_mruby_ctx_t *ctx = ngx_mrb_http_get_module_ctx(filter_data->state->mrb, r);
  ctx->set_var_target = filter_data->target;

  if (filter_data->state == NGX_CONF_UNSET_PTR) {
    return NGX_DECLINED;
  }

  if (filter_data->code == NGX_CONF_UNSET_PTR) {
    return NGX_DECLINED;
  }
  ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "hooked mruby file-based set_handler code: %s",
                filter_data->code->code.file);
  return ngx_mrb_run(r, filter_data->state, filter_data->code, mlcf->cached, val, NGX_HTTP_MRUBY_HANDLER_SET);
}

static ngx_int_t ngx_http_mruby_set_inline_handler(ngx_http_request_t *r, ngx_str_t *val, ngx_http_variable_value_t *v,
                                                   void *data)
{
  ngx_http_mruby_set_var_data_t *filter_data;
  filter_data = data;
  ngx_http_mruby_ctx_t *ctx = ngx_mrb_http_get_module_ctx(filter_data->state->mrb, r);
  ctx->set_var_target = filter_data->target;

  ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "hooked mruby inline set_handler code: %s",
                filter_data->code->code.string);
  return ngx_mrb_run(r, filter_data->state, filter_data->code, 1, val, NGX_HTTP_MRUBY_HANDLER_SET);
}
#endif

/*
// ngx_mruby mruby filter functions
*/

static void ngx_http_mruby_header_filter_init(void)
{
  ngx_http_next_header_filter = ngx_http_top_header_filter;
  ngx_http_top_header_filter = ngx_http_mruby_header_filter;
}

static void ngx_http_mruby_body_filter_init(void)
{
  ngx_http_next_body_filter = ngx_http_top_body_filter;
  ngx_http_top_body_filter = ngx_http_mruby_body_filter;
}

static void ngx_http_mruby_filter_cleanup(void *data)
{
  ngx_http_mruby_ctx_t *ctx;
  ctx = (ngx_http_mruby_ctx_t *)data;
  ngx_memzero(ctx, sizeof(ngx_http_mruby_ctx_t));
}

static ngx_int_t ngx_http_mruby_body_filter_handler_inner(ngx_http_request_t *r, ngx_chain_t *in, code_type_t type)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
  ngx_http_mruby_ctx_t *ctx = ngx_mrb_http_get_module_ctx(NULL, r);

  ngx_int_t rc;

  if (ctx == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate context %s:%d", __FUNCTION__, __LINE__);
    return NGX_ERROR;
  }

  if (ctx->phase == NGX_HTTP_MRUBY_FILTER_PASS) {
    return ngx_http_next_body_filter(r, in);
  }
  ctx->phase = NGX_HTTP_MRUBY_FILTER_PROCESS;

  if ((rc = ngx_http_mruby_read_body(r, in, ctx)) != NGX_OK) {
    if (rc == NGX_AGAIN) {
      ctx->phase = NGX_HTTP_MRUBY_FILTER_READ;
      return NGX_OK;
    }
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to read body %s:%d", __FUNCTION__, __LINE__);
    return NGX_ERROR;
  }

  r->connection->buffered &= ~0x08;

  if (type == NGX_MRB_CODE_TYPE_FILE) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "hooked mruby file-based body_filter_handler code: %s",
                  mlcf->body_filter_code->code.file);
    rc = ngx_mrb_run(r, mmcf->state, mlcf->body_filter_code, mlcf->cached, NULL, NGX_HTTP_MRUBY_HANDLER_BODY_FILTER);
  } else {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "hooked mruby inline body_filter_inline_handler code: %s",
                  mlcf->body_filter_inline_code->code.string);

    rc = ngx_mrb_run(r, mmcf->state, mlcf->body_filter_inline_code, mlcf->cached, NULL,
                     NGX_HTTP_MRUBY_HANDLER_BODY_FILTER);
  }

  if (rc == NGX_ERROR) {
    return NGX_ERROR;
  }
  return ngx_mrb_finalize_body_filter(r, ctx);
}

static ngx_int_t ngx_http_mruby_body_filter_handler(ngx_http_request_t *r, ngx_chain_t *in)
{
  return ngx_http_mruby_body_filter_handler_inner(r, in, NGX_MRB_CODE_TYPE_FILE);
}

static ngx_int_t ngx_http_mruby_body_filter_inline_handler(ngx_http_request_t *r, ngx_chain_t *in)
{
  return ngx_http_mruby_body_filter_handler_inner(r, in, NGX_MRB_CODE_TYPE_STRING);
}

/*
 * Passes the header on after the code of an mruby header filter has run,
 * unless an mruby body filter is configured too. The body filter can change
 * the length of the body, so the header then waits, as it does in a location
 * with only a body filter (ngx_http_mruby_header_filter), and
 * ngx_mrb_finalize_body_filter sends it with the length of the body that the
 * body filter produced; ngx_http_mruby_body_filter sends it for a response
 * without a known length. The changes that the header filter code made to
 * headers_out go out with it.
 */
static ngx_int_t ngx_http_mruby_header_filter_send(ngx_http_request_t *r, ngx_http_mruby_loc_conf_t *mlcf)
{
  ngx_int_t rc;

  if (mlcf->body_filter_handler != NULL) {
    return NGX_OK;
  }

  rc = ngx_http_next_header_filter(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    return NGX_ERROR;
  }
  return rc;
}

static ngx_int_t ngx_http_mruby_header_filter_handler(ngx_http_request_t *r, ngx_chain_t *in)
{
  ngx_int_t rc;
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);

  rc = ngx_mrb_run(r, mmcf->state, mlcf->header_filter_code, mlcf->cached, NULL, NGX_HTTP_MRUBY_HANDLER_HEADER_FILTER);
  if (rc == NGX_ERROR) {
    return NGX_ERROR;
  }

  return ngx_http_mruby_header_filter_send(r, mlcf);
}

static ngx_int_t ngx_http_mruby_header_filter_inline_handler(ngx_http_request_t *r, ngx_chain_t *in)
{
  ngx_int_t rc;
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);

  rc = ngx_mrb_run(r, mmcf->state, mlcf->header_filter_inline_code, mlcf->cached, NULL,
                   NGX_HTTP_MRUBY_HANDLER_HEADER_FILTER);
  if (rc == NGX_ERROR) {
    return NGX_ERROR;
  }

  return ngx_http_mruby_header_filter_send(r, mlcf);
}

static ngx_int_t ngx_http_mruby_header_filter(ngx_http_request_t *r)
{
  ngx_http_mruby_loc_conf_t *mlcf;
  ngx_http_mruby_ctx_t *ctx;
  ngx_pool_cleanup_t *cln;
  ngx_int_t rc;

  mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);

  if (mlcf->header_filter_handler == NULL && mlcf->body_filter_handler == NULL) {
    return ngx_http_next_header_filter(r);
  } else {
    r->filter_need_in_memory = 1;
  }

  ctx = ngx_mrb_http_get_module_ctx(NULL, r);
  if (ctx == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory from r->pool %s:%d", __FUNCTION__,
                  __LINE__);
    return NGX_ERROR;
  }
  /* once the body filter has a body buffer, body_length is that buffer's length */
  if (ctx->body == NULL) {
    ctx->body_length = r->headers_out.content_length_n;
  }

  cln = ngx_pool_cleanup_add(r->pool, 0);
  if (cln == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory from r->pool %s:%d", __FUNCTION__,
                  __LINE__);
    return NGX_ERROR;
  }
  cln->handler = ngx_http_mruby_filter_cleanup;
  cln->data = ctx;

  if (mlcf->header_filter_handler == NULL) {
    return NGX_OK;
  }

  rc = mlcf->header_filter_handler(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    return rc;
  }

  if (ctx->body == NULL) {
    ctx->body_length = r->headers_out.content_length_n;
  }
  return rc;
}

static ngx_int_t ngx_http_mruby_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
  ngx_http_mruby_loc_conf_t *mlcf;
  ngx_http_mruby_ctx_t *ctx;
  ngx_pool_cleanup_t *cln;
  ngx_int_t rc;

  mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
  if (mlcf->body_filter_handler == NULL || r->headers_out.content_length_n < 0) {
    if (r->headers_out.content_length_n < 0) {
      ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                    "body filter don't support chunked response, go to next filter %s:%d", __FUNCTION__, __LINE__);
    }

    if (mlcf->body_filter_handler != NULL) {
      rc = ngx_http_next_header_filter(r);
      if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return NGX_ERROR;
      }
    }
    return ngx_http_next_body_filter(r, in);
  }

  ctx = ngx_mrb_http_get_module_ctx(NULL, r);
  if (ctx == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory from r->pool %s:%d", __FUNCTION__,
                  __LINE__);
    return NGX_ERROR;
  }

  cln = ngx_pool_cleanup_add(r->pool, 0);
  if (cln == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory from r->pool %s:%d", __FUNCTION__,
                  __LINE__);
    return NGX_ERROR;
  }
  cln->handler = ngx_http_mruby_filter_cleanup;
  cln->data = ctx;

  rc = mlcf->body_filter_handler(r, in);
  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "body filter handler return code=(%d) %s:%d", rc, __FUNCTION__,
                __LINE__);
  return rc;
}

static ngx_int_t ngx_http_mruby_read_body(ngx_http_request_t *r, ngx_chain_t *in, ngx_http_mruby_ctx_t *ctx)
{
  u_char *p;
  size_t size, rest;
  ngx_buf_t *b;
  ngx_chain_t *cl;

  if (ctx->body == NULL && r->headers_out.content_length_n > 0) {
    ctx->body = ngx_pcalloc(r->pool, ctx->body_length);
    if (ctx->body == NULL) {
      return NGX_ERROR;
    }
    ctx->last = ctx->body;
  }
  p = ctx->last;

  for (cl = in; cl != NULL; cl = cl->next) {
    b = cl->buf;
    size = b->last - b->pos;
    rest = ctx->body + ctx->body_length - p;
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "%s DEBUG %s:%d: filter buf: %uz rest: %uz", MODULE_NAME,
                  __func__, __LINE__, size, rest);
    size = (rest < size) ? rest : size;
    // ctx->body is NULL for a response of length 0, and memcpy() must not get
    // NULL even for 0 bytes
    if (size > 0) {
      p = ngx_cpymem(p, b->pos, size);
      b->pos += size;
    }
    if (b->last_buf) {
      ctx->last = p;
      ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "%s DEBUG %s:%d: reached last buffer", MODULE_NAME, __func__,
                    __LINE__);

      return NGX_OK;
    }
    if (r->upstream && size == rest) {
      ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                    "%s DEBUG %s:%d: is not last buffer, but upstream buffer reached", MODULE_NAME, __func__, __LINE__);
      return NGX_OK;
    }
  }

  ctx->last = p;
  r->connection->buffered |= 0x08;

  return NGX_AGAIN;
}

#if (NGX_HTTP_SSL) && OPENSSL_VERSION_NUMBER >= 0x1000205fL

static int ngx_http_mruby_set_der_certificate_data(ngx_ssl_conn_t *ssl_conn, ngx_str_t *cert, ngx_str_t *key)
{
  BIO *bio = NULL;
  EVP_PKEY *pkey = NULL;
  X509 *x509 = NULL;
  u_long n;

  /* read certificate data from memory buffer */
  if ((bio = BIO_new_mem_buf(cert->data, cert->len)) == NULL) {
    goto NGX_MRUBY_SSL_ERROR;
  }

  if ((x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL)) == NULL) {
    goto NGX_MRUBY_SSL_ERROR;
  }

  SSL_certs_clear(ssl_conn);

  if (SSL_use_certificate(ssl_conn, x509) == 0) {
    goto NGX_MRUBY_SSL_ERROR;
  }

  X509_free(x509);
  x509 = NULL;

  /* read rest of the chain */
  while (!BIO_eof(bio)) {
    x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
      n = ERR_peek_last_error();

      if (ERR_GET_LIB(n) == ERR_LIB_PEM && ERR_GET_REASON(n) == PEM_R_NO_START_LINE) {
        ERR_clear_error();
        break;
      }

      goto NGX_MRUBY_SSL_ERROR;
    }

    if (SSL_add0_chain_cert(ssl_conn, x509) == 0) {
      goto NGX_MRUBY_SSL_ERROR;
    }
  }

  BIO_free(bio);
  bio = NULL;

  /* read key data from memory buffer */
  if ((bio = BIO_new_mem_buf(key->data, key->len)) == NULL) {
    goto NGX_MRUBY_SSL_ERROR;
  }

  if ((pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)) == NULL) {
    goto NGX_MRUBY_SSL_ERROR;
  }

  if (SSL_use_PrivateKey(ssl_conn, pkey) != 1) {
    goto NGX_MRUBY_SSL_ERROR;
  }

  BIO_free(bio);
  bio = NULL;

  EVP_PKEY_free(pkey);
  pkey = NULL;

  return NGX_OK;

NGX_MRUBY_SSL_ERROR:
  if (pkey)
    EVP_PKEY_free(pkey);
  if (bio)
    BIO_free(bio);
  if (x509)
    X509_free(x509);
  return NGX_ERROR;
}

static int ngx_http_mruby_set_der_certificate(ngx_ssl_conn_t *ssl_conn, ngx_str_t *cert, ngx_str_t *key)
{
  BIO *bio = NULL;
  X509 *x509 = NULL;
  u_long n;

  bio = BIO_new_file((char *)cert->data, "r");
  if (bio == NULL) {
    goto NGX_MRUBY_SSL_ERROR;
  }

  x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
  if (x509 == NULL) {
    goto NGX_MRUBY_SSL_ERROR;
  }

  SSL_certs_clear(ssl_conn);

  if (SSL_use_certificate(ssl_conn, x509) == 0) {
    goto NGX_MRUBY_SSL_ERROR;
  }

  X509_free(x509);
  x509 = NULL;

  /* read rest of the chain */
  for (;;) {
    x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
      n = ERR_peek_last_error();

      if (ERR_GET_LIB(n) == ERR_LIB_PEM && ERR_GET_REASON(n) == PEM_R_NO_START_LINE) {
        ERR_clear_error();
        break;
      }

      goto NGX_MRUBY_SSL_ERROR;
    }

    if (SSL_add0_chain_cert(ssl_conn, x509) == 0) {
      goto NGX_MRUBY_SSL_ERROR;
    }
  }

  BIO_free(bio);
  bio = NULL;

  if (SSL_use_PrivateKey_file(ssl_conn, (char *)key->data, SSL_FILETYPE_PEM) != 1) {
    goto NGX_MRUBY_SSL_ERROR;
  }

  return NGX_OK;

NGX_MRUBY_SSL_ERROR:
  if (bio)
    BIO_free(bio);
  if (x509)
    X509_free(x509);
  return NGX_ERROR;
}

#endif /* NGX_HTTP_SSL */

#if (NGX_HTTP_SSL)

#if OPENSSL_VERSION_NUMBER >= 0x1000205fL
/*
 * Nginx::SSL keeps the state of the handshake being handled in the shared
 * server configuration. It is valid only while the handler code runs: reset
 * it before the code runs and clear it before returning, so that Nginx::SSL
 * methods called at any other time raise instead of reading a finished
 * handshake (whose servername lived on this function's stack and whose
 * certificate strings were allocated from the connection pool).
 */
static void ngx_http_mruby_ssl_handshake_state_clear(ngx_http_mruby_srv_conf_t *mscf)
{
  mscf->connection = NULL;
  mscf->servername = NULL;
  ngx_str_null(&mscf->cert_path);
  ngx_str_null(&mscf->cert_key_path);
  ngx_str_null(&mscf->cert_data);
  ngx_str_null(&mscf->cert_key_data);
}

static ngx_int_t ngx_http_mruby_ssl_handshake_run(ngx_http_mruby_srv_conf_t *mscf, ngx_connection_t *c)
{
  mrb_state *mrb = mscf->state->mrb;
  mrb_int ai;
  ngx_http_request_t *prev_r;
  ngx_int_t rc = NGX_OK;

  ai = mrb_gc_arena_save(mrb);
  if (mscf->ssl_handshake_code != NGX_CONF_UNSET_PTR && !mscf->ssl_handshake_code->cache) {
    rc = ngx_http_mruby_state_reinit_from_file(mscf->state, mscf->ssl_handshake_code);
    if (rc != NGX_OK) {
      ngx_log_error(NGX_LOG_ERR, c->log, 0, MODULE_NAME " : mruby ssl handler: failed to recompile %s, rc=%d",
                    mscf->ssl_handshake_code->code.file, rc);
      ngx_mrb_state_clean(NULL, mscf->state);
      mrb_gc_arena_restore(mrb, ai);
      return NGX_DECLINED;
    }
  }

  /* the handshake handler runs outside of any request */
  prev_r = ngx_mrb_get_request();
  ngx_mrb_push_request(NULL);
  if (mscf->ssl_handshake_code != NGX_CONF_UNSET_PTR) {
    mrb_toplevel_run(mrb, mscf->ssl_handshake_code->proc);
  }
  if (mscf->ssl_handshake_inline_code != NGX_CONF_UNSET_PTR) {
    mrb_toplevel_run(mrb, mscf->ssl_handshake_inline_code->proc);
  }
  ngx_mrb_push_request(prev_r);

  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mrb, mscf->ssl_handshake_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mrb, mscf->ssl_handshake_inline_code);
  if (mrb->exc) {
    ngx_mrb_raise_connection_error(mrb, mrb_obj_value(mrb->exc), c);
    rc = NGX_ERROR;
  }
  ngx_mrb_state_clean(NULL, mscf->state);
  mrb_gc_arena_restore(mrb, ai);

  return rc;
}

static int ngx_http_mruby_ssl_cert_handler(ngx_ssl_conn_t *ssl_conn, void *data)
{
  ngx_connection_t *c;
  ngx_http_connection_t *hc;
  const char *servername;
  ngx_http_mruby_srv_conf_t *mscf;
  ngx_str_t host;
  ngx_str_t cert_path, cert_key_path, cert_data, cert_key_data;
  void *prev_ud;
  int rc;

  c = ngx_ssl_get_connection(ssl_conn);
  if (c == NULL) {
    return 0;
  }

  hc = c->data;
  if (NULL == hc) {
    ngx_log_error(NGX_LOG_ERR, c->log, 0, MODULE_NAME " : mruby ssl handler: ssl connection data hc NULL");
    return 0;
  }

  host.len = 0;
  host.data = NULL;
  servername = SSL_get_servername(ssl_conn, TLSEXT_NAMETYPE_host_name);

  if (servername == NULL) {
    ngx_log_error(NGX_LOG_DEBUG, c->log, 0, MODULE_NAME " : mruby ssl handler: SSL server name NULL");
  } else {
    host.len = ngx_strlen(servername);
    if (host.len == 0) {
      ngx_log_error(NGX_LOG_DEBUG, c->log, 0, MODULE_NAME " : mruby ssl handler: host len == 0");
      return 1;
    }
    host.data = (u_char *)servername;
    ngx_log_error(NGX_LOG_DEBUG, c->log, 0, MODULE_NAME " : mruby ssl handler: servername \"%V\"", &host);
  }

  mscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_mruby_module);
  if (NULL == mscf) {
    ngx_log_error(NGX_LOG_ERR, c->log, 0, MODULE_NAME " : mruby ssl handler: mscf NULL");
    return 1;
  }

  if (mscf->ssl_handshake_code == NGX_CONF_UNSET_PTR && mscf->ssl_handshake_inline_code == NGX_CONF_UNSET_PTR) {
    ngx_log_error(NGX_LOG_ERR, c->log, 0, MODULE_NAME " : mruby ssl handler: unexpected error, mruby code not found");
    return 1;
  }

  ngx_http_mruby_ssl_handshake_state_clear(mscf);
  mscf->connection = c;
  mscf->servername = &host;
  prev_ud = mscf->state->mrb->ud;
  mscf->state->mrb->ud = mscf;

  rc = ngx_http_mruby_ssl_handshake_run(mscf, c);

  mscf->state->mrb->ud = prev_ud;

  /* the certificate strings stay valid until c->pool is destroyed */
  cert_path = mscf->cert_path;
  cert_key_path = mscf->cert_key_path;
  cert_data = mscf->cert_data;
  cert_key_data = mscf->cert_key_data;
  ngx_http_mruby_ssl_handshake_state_clear(mscf);

  if (rc == NGX_DECLINED) {
    return 1;
  }
  if (rc != NGX_OK) {
    return 0;
  }

  if (cert_data.len == 0 || cert_key_data.len == 0) {
    if (cert_path.len == 0 || cert_key_path.len == 0) {
      ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
                    MODULE_NAME " : mruby ssl handler: cert or cert key not exists or not read");
      return 1;
    }

    errno = 0;
    if (access((const char *)cert_path.data, F_OK | R_OK) != 0) {
      if (errno == EACCES) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, MODULE_NAME " : mruby ssl handler: cert [%V] permission denied",
                      &cert_path);
      } else {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, MODULE_NAME " : mruby ssl handler: cert [%V] not exists or not read",
                      &cert_path);
      }
      return 0;
    }
    errno = 0;
    if (access((const char *)cert_key_path.data, F_OK | R_OK) != 0) {
      if (errno == EACCES) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, MODULE_NAME " : mruby ssl handler: cert_key [%V] permission denied",
                      &cert_key_path);
      } else {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, MODULE_NAME " : mruby ssl handler: cert_key [%V] not exists or not read",
                      &cert_key_path);
      }
      return 0;
    }

    ngx_log_error(NGX_LOG_DEBUG, c->log, 0, MODULE_NAME " : mruby ssl handler: changing certificate to cert=%V key=%V",
                  &cert_path, &cert_key_path);
    rc = ngx_http_mruby_set_der_certificate(ssl_conn, &cert_path, &cert_key_path);
  } else {
    ngx_log_error(NGX_LOG_DEBUG, c->log, 0, MODULE_NAME " : mruby ssl handler: changing certificate by mem buffer");
    rc = ngx_http_mruby_set_der_certificate_data(ssl_conn, &cert_data, &cert_key_data);
  }
  if (rc != NGX_OK) {
    ngx_log_error(NGX_LOG_ERR, c->log, 0, MODULE_NAME " : mruby ssl handler: failed to change certificate.\n");
    return 0;
  }

  return 1;
}
#endif /* 0x1000205fL */
#endif /* NGX_HTTP_SSL */
