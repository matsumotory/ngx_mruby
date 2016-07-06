/*
** ngx_mruby - A Web Server Extension Mechanism Using mruby
**
** See Copyright Notice in LEGAL
*/

#include <nginx.h>
#include <ngx_conf_file.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_mruby_core.h"
#include "ngx_http_mruby_module.h"
#include "ngx_http_mruby_request.h"

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/compile.h>
#include <mruby/data.h>
#include <mruby/proc.h>
#include <mruby/string.h>
#include <mruby/value.h>
#include <mruby/version.h>

#define ON 1
#define OFF 0

#define NGX_MRUBY_MERGE_CODE(prev_code, conf_code)                                                                     \
  if (prev_code == NGX_CONF_UNSET_PTR) {                                                                               \
    prev_code = conf_code;                                                                                             \
  }

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
                             ngx_str_t *result);
static ngx_int_t ngx_mrb_run_cycle(ngx_cycle_t *cycle, ngx_mrb_state_t *state, ngx_mrb_code_t *code);
static ngx_int_t ngx_mrb_run_conf(ngx_conf_t *cf, ngx_mrb_state_t *state, ngx_mrb_code_t *code);
// static ngx_int_t ngx_mrb_output_filter_run(ngx_http_request_t *r, ngx_mrb_state_t *state, ngx_mrb_code_t *code,
// ngx_flag_t cached);

/*
// ngx_mruby mruby state functions
*/
#define NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(cached, state, code, reinit)                                              \
  do {                                                                                                                 \
    if (!cached) {                                                                                                     \
      if (state == NGX_CONF_UNSET_PTR) {                                                                               \
        return NGX_DECLINED;                                                                                           \
      }                                                                                                                \
      if (code == NGX_CONF_UNSET_PTR) {                                                                                \
        return NGX_DECLINED;                                                                                           \
      }                                                                                                                \
      if (reinit(state, code) == NGX_ERROR) {                                                                          \
        return NGX_ERROR;                                                                                              \
      }                                                                                                                \
    }                                                                                                                  \
  } while (0)

static ngx_int_t ngx_http_mruby_state_reinit_from_file(ngx_mrb_state_t *state, ngx_mrb_code_t *code);
static ngx_mrb_code_t *ngx_http_mruby_mrb_code_from_file(ngx_pool_t *pool, ngx_str_t *code_file_path);
static ngx_mrb_code_t *ngx_http_mruby_mrb_code_from_string(ngx_pool_t *pool, ngx_str_t *code_s);
static ngx_int_t ngx_http_mruby_shared_state_init(ngx_mrb_state_t *state);
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
static char *ngx_http_mruby_ssl_handshake_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
#endif /* NGX_HTTP_SSL */

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

#if (NGX_HTTP_SSL) && OPENSSL_VERSION_NUMBER >= 0x1000205fL
static int ngx_http_mruby_ssl_cert_handler(ngx_ssl_conn_t *ssl_conn, void *data);
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
static ngx_int_t ngx_http_mruby_body_filter_handler(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_mruby_body_filter_inline_handler(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_mruby_header_filter_handler(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_mruby_header_filter_inline_handler(ngx_http_request_t *r, ngx_chain_t *in);

static ngx_command_t ngx_http_mruby_commands[] = {

#if (NGX_HTTP_SSL)

    /* server config */
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

    {ngx_string("mruby_post_read_handler"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE12,
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

    {ngx_string("mruby_post_read_handler_code"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
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

extern ngx_http_request_t *ngx_mruby_request;

static void ngx_http_mruby_cleanup(void *data)
{
  mrb_state *mrb = data;

  mrb_close(mrb);
}

static void *ngx_http_mruby_create_main_conf(ngx_conf_t *cf)
{
  ngx_http_mruby_main_conf_t *mmcf;

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

  return mmcf;
}

static char *ngx_http_mruby_init_main_conf(ngx_conf_t *cf, void *conf)
{
  return NGX_CONF_OK;
}

/* create server config phase */

static void *ngx_http_mruby_create_srv_conf(ngx_conf_t *cf)
{
  ngx_http_mruby_srv_conf_t *mscf;

  mscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mruby_srv_conf_t));
  if (mscf == NULL) {
    return NULL;
  }

  mscf->state = ngx_pcalloc(cf->pool, sizeof(ngx_mrb_state_t));
  if (mscf->state == NULL) {
    return NULL;
  }

  mscf->cert_path.len = 0;
  mscf->cert_key_path.len = 0;
  mscf->cert_data.len = 0;
  mscf->cert_key_data.len = 0;
  mscf->ssl_handshake_code = NGX_CONF_UNSET_PTR;

  return mscf;
}

static char *ngx_http_mruby_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
#if (NGX_HTTP_SSL)

  ngx_http_mruby_srv_conf_t *prev = parent;
  ngx_http_mruby_srv_conf_t *conf = child;
  ngx_http_ssl_srv_conf_t *sscf;

  NGX_MRUBY_MERGE_CODE(prev->ssl_handshake_code, conf->ssl_handshake_code);

  if (conf->ssl_handshake_code != NGX_CONF_UNSET_PTR) {
    sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
    if (sscf == NULL || sscf->ssl.ctx == NULL) {
      ngx_log_error(NGX_LOG_EMERG, cf->log, 0, MODULE_NAME " : no ssl configured for the server");
      return NGX_CONF_ERROR;
    }

#if OPENSSL_VERSION_NUMBER >= 0x1000205fL
    SSL_CTX_set_cert_cb(sscf->ssl.ctx, ngx_http_mruby_ssl_cert_handler, NULL);
#else
    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                  MODULE_NAME " : OpenSSL 1.0.2e or later required but found " OPENSSL_VERSION_TEXT);
    return NGX_CONF_ERROR;
#endif
  }

#endif /* NGX_HTTP_SSL */

  return NGX_CONF_OK;
}

/* create location config phase */
static void *ngx_http_mruby_create_loc_conf(ngx_conf_t *cf)
{
  ngx_http_mruby_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mruby_loc_conf_t));
  if (conf == NULL) {
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

  return conf;
}

static char *ngx_http_mruby_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_mruby_loc_conf_t *prev = parent;
  ngx_http_mruby_loc_conf_t *conf = child;

  NGX_MRUBY_MERGE_CODE(prev->post_read_code, conf->post_read_code);
  NGX_MRUBY_MERGE_CODE(prev->server_rewrite_code, conf->server_rewrite_code);
  NGX_MRUBY_MERGE_CODE(prev->rewrite_code, conf->rewrite_code);
  NGX_MRUBY_MERGE_CODE(prev->access_code, conf->access_code);
  NGX_MRUBY_MERGE_CODE(prev->content_code, conf->content_code);
  NGX_MRUBY_MERGE_CODE(prev->log_code, conf->log_code);

  NGX_MRUBY_MERGE_CODE(prev->post_read_inline_code, conf->post_read_inline_code);
  NGX_MRUBY_MERGE_CODE(prev->server_rewrite_inline_code, conf->server_rewrite_inline_code);
  NGX_MRUBY_MERGE_CODE(prev->rewrite_inline_code, conf->rewrite_inline_code);
  NGX_MRUBY_MERGE_CODE(prev->access_inline_code, conf->access_inline_code);
  NGX_MRUBY_MERGE_CODE(prev->content_inline_code, conf->content_inline_code);
  NGX_MRUBY_MERGE_CODE(prev->log_inline_code, conf->log_inline_code);

  NGX_MRUBY_MERGE_CODE(prev->body_filter_code, conf->body_filter_code);
  NGX_MRUBY_MERGE_CODE(prev->body_filter_inline_code, conf->body_filter_inline_code);
  NGX_MRUBY_MERGE_CODE(prev->header_filter_code, conf->header_filter_code);
  NGX_MRUBY_MERGE_CODE(prev->header_filter_inline_code, conf->header_filter_inline_code);

  ngx_conf_merge_value(conf->cached, prev->cached, 0);
  ngx_conf_merge_value(conf->add_handler, prev->add_handler, 0);

  return NGX_CONF_OK;
}

static ngx_int_t ngx_http_mruby_preinit(ngx_conf_t *cf)
{
  ngx_int_t rc;
  ngx_http_mruby_main_conf_t *mmcf;
  ngx_pool_cleanup_t *cln;

  cln = ngx_pool_cleanup_add(cf->pool, 0);
  if (cln == NULL) {
    return NGX_ERROR;
  }

  mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  rc = ngx_http_mruby_shared_state_init(mmcf->state);
  if (rc == NGX_ERROR) {
    return NGX_ERROR;
  }

  cln->handler = ngx_http_mruby_cleanup;
  cln->data = mmcf->state->mrb;

  return NGX_OK;
}

static ngx_int_t ngx_http_mruby_init(ngx_conf_t *cf)
{
  ngx_http_core_main_conf_t *cmcf;
  ngx_http_mruby_main_conf_t *mmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);

  ngx_mruby_request = NULL;

  ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "%s/%s (%s/%s) mechanism enabled", MODULE_NAME, MODULE_VERSION,
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

  if (mmcf->init_worker_code != NGX_CONF_UNSET_PTR) {
    return ngx_mrb_run_cycle(cycle, mmcf->state, mmcf->init_worker_code);
  }

  return NGX_OK;
}

static void ngx_http_mruby_exit_worker(ngx_cycle_t *cycle)
{
  ngx_http_mruby_main_conf_t *mmcf;

  mmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_mruby_module);

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
      NGX_HTTP_SERVER_REWRITE_PHASE, NGX_HTTP_REWRITE_PHASE,
      // NGX_HTTP_POST_REWRITE_PHASE,
      // NGX_HTTP_PREACCESS_PHASE,
      NGX_HTTP_ACCESS_PHASE,
      // NGX_HTTP_POST_ACCESS_PHASE,
      // NGX_HTTP_TRY_FILES_PHASE,
      NGX_HTTP_CONTENT_PHASE, NGX_HTTP_LOG_PHASE,
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
  // mrb_irep_decref(state->mrb, code->proc->body.irep);
  mrbc_context_free(state->mrb, code->ctx);
}

ngx_int_t ngx_mrb_run_cycle(ngx_cycle_t *cycle, ngx_mrb_state_t *state, ngx_mrb_code_t *code)
{
  int ai = mrb_gc_arena_save(state->mrb);
  ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "%s INFO %s:%d: mrb_run", MODULE_NAME, __func__, __LINE__);
  mrb_run(state->mrb, code->proc, mrb_top_self(state->mrb));
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
  mrb_run(state->mrb, code->proc, mrb_top_self(state->mrb));
  if (state->mrb->exc) {
    ngx_mrb_raise_conf_error(state->mrb, mrb_obj_value(state->mrb->exc), cf);
    mrb_gc_arena_restore(state->mrb, ai);
    return NGX_ERROR;
  }

  mrb_gc_arena_restore(state->mrb, ai);
  return NGX_OK;
}

ngx_int_t ngx_mrb_run(ngx_http_request_t *r, ngx_mrb_state_t *state, ngx_mrb_code_t *code, ngx_flag_t cached,
                      ngx_str_t *result)
{
  int result_len;
  int ai = 0;
  int exc_ai = 0;
  mrb_value mrb_result;
  ngx_http_mruby_ctx_t *ctx;
  ngx_mrb_rputs_chain_list_t *chain;

  if (state == NGX_CONF_UNSET_PTR || code == NGX_CONF_UNSET_PTR) {
    return NGX_DECLINED;
  }
  ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);
  if (ctx == NULL && (ctx = ngx_pcalloc(r->pool, sizeof(*ctx))) == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory from r->pool %s:%d", __FUNCTION__,
                  __LINE__);
    return NGX_ERROR;
  }
  ngx_http_set_ctx(r, ctx, ngx_http_mruby_module);
  ngx_mrb_push_request(r);

  if (!cached && !code->cache) {
    ai = mrb_gc_arena_save(state->mrb);
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s INFO %s:%d: mrb_run info: ai=%d", MODULE_NAME, __func__,
                  __LINE__, ai);
  }
  exc_ai = mrb_gc_arena_save(state->mrb);
  mrb_result = mrb_run(state->mrb, code->proc, mrb_top_self(state->mrb));
  if (state->mrb->exc) {
    ngx_mrb_raise_error(state->mrb, mrb_obj_value(state->mrb->exc), r);
    r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    mrb_gc_arena_restore(state->mrb, exc_ai);
  } else if (result != NULL) {
    if (mrb_nil_p(mrb_result)) {
      result->data = NULL;
      result->len = 0;
    } else {
      if (mrb_type(mrb_result) != MRB_TT_STRING) {
        mrb_result = mrb_funcall(state->mrb, mrb_result, "to_s", 0, NULL);
      }
      result_len = RSTRING_LEN(mrb_result);
      result->data = ngx_palloc(r->pool, result_len);
      if (result->data == NULL) {
        return NGX_ERROR;
      }
      ngx_memcpy(result->data, (u_char *)mrb_str_to_cstr(state->mrb, mrb_result), result_len);
      result->len = result_len;
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s INFO %s:%d: mrb_run info: return value=(%s)", MODULE_NAME,
                    __func__, __LINE__, mrb_str_to_cstr(state->mrb, mrb_result));
      mrb_gc_arena_restore(state->mrb, exc_ai);
      return NGX_OK;
    }
  }

  if (!cached && !code->cache) {
    ngx_mrb_code_clean(r, state, code);
    // mrb_gc_arena_restore(state->mrb, ai);
  }
  ngx_mrb_state_clean(r, state);

  // TODO: Support rputs by multi directive
  if (ngx_http_get_module_ctx(r, ngx_http_mruby_module) != NULL) {
    chain = ctx->rputs_chain;
    if (chain == NULL) {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "%s INFO %s:%d: mrb_run info: rputs_chain is null and return NGX_OK", MODULE_NAME, __func__,
                    __LINE__);
      if (r->headers_out.status >= 100) {
        return r->headers_out.status;
      } else {
        return NGX_OK;
      }
    }
    if (r->headers_out.status == NGX_HTTP_OK || !(*chain->last)->buf->last_buf) {
      r->headers_out.status = NGX_HTTP_OK;
      (*chain->last)->buf->last_buf = 1;
      ngx_http_send_header(r);
      ngx_http_output_filter(r, chain->out);
      ngx_http_set_ctx(r, NULL, ngx_http_mruby_module);
      return NGX_OK;
    } else {
      return r->headers_out.status;
    }
  }
  return NGX_OK;
}

/*
static ngx_int_t ngx_mrb_output_filter_run(ngx_http_request_t *r, ngx_mrb_state_t *state, ngx_mrb_code_t *code,
                                           ngx_flag_t cached)
{
  int ai = 0;
  int exc_ai = 0;
  ngx_http_mruby_ctx_t *ctx;

  if (state == NGX_CONF_UNSET_PTR || code == NGX_CONF_UNSET_PTR) {
    return NGX_DECLINED;
  }
  ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);
  if (ctx == NULL && (ctx = ngx_pcalloc(r->pool, sizeof(*ctx))) == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory from r->pool %s:%d", __FUNCTION__,
                  __LINE__);
    return NGX_ERROR;
  }
  ngx_http_set_ctx(r, ctx, ngx_http_mruby_module);
  ngx_mrb_push_request(r);

  if (!cached && !code->cache) {
    ai = mrb_gc_arena_save(state->mrb);
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s INFO %s:%d: mrb_run info: ai=%d", MODULE_NAME, __func__,
                  __LINE__, ai);
  }
  exc_ai = mrb_gc_arena_save(state->mrb);
  mrb_run(state->mrb, code->proc, mrb_top_self(state->mrb));
  if (state->mrb->exc) {
    ngx_mrb_raise_error(state->mrb, mrb_obj_value(state->mrb->exc), r);
    r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    mrb_gc_arena_restore(state->mrb, exc_ai);
  }

  if (!cached && !code->cache) {
    ngx_mrb_code_clean(r, state, code);
    // mrb_gc_arena_restore(state->mrb, ai);
  }
  ngx_mrb_state_clean(r, state);

  return NGX_OK;
}
*/

/*
// ngx_mruby mruby state functions
*/

static ngx_int_t ngx_mrb_gencode_state(ngx_mrb_state_t *state, ngx_mrb_code_t *code)
{
  int ai;
  FILE *mrb_file;
  struct mrb_parser_state *p;

  if ((mrb_file = fopen((char *)code->code.file, "r")) == NULL) {
    return NGX_ERROR;
  }

  ai = mrb_gc_arena_save(state->mrb);
  code->ctx = mrbc_context_new(state->mrb);
  mrbc_filename(state->mrb, code->ctx, (char *)code->code.file);
  p = mrb_parse_file(state->mrb, mrb_file, code->ctx);
  fclose(mrb_file);
  if (p == NULL) {
    return NGX_ERROR;
  }
  code->proc = mrb_generate_code(state->mrb, p);
  mrb_pool_close(p->pool);
  if (code->proc == NULL) {
    return NGX_ERROR;
  }

  mrb_gc_arena_restore(state->mrb, ai);

  return NGX_OK;
}

static ngx_int_t ngx_http_mruby_state_reinit_from_file(ngx_mrb_state_t *state, ngx_mrb_code_t *code)
{
  if (state == NGX_CONF_UNSET_PTR) {
    return NGX_ERROR;
  }
  if (ngx_mrb_gencode_state(state, code) != NGX_OK) {
    return NGX_ERROR;
  }
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

static ngx_int_t ngx_http_mruby_shared_state_init(ngx_mrb_state_t *state)
{
  mrb_state *mrb;

  mrb = mrb_open();
  if (mrb == NULL) {
    return NGX_ERROR;
  }
  ngx_mrb_class_init(mrb);

  state->mrb = mrb;

  return NGX_OK;
}

static ngx_int_t ngx_http_mruby_shared_state_compile(ngx_conf_t *cf, ngx_mrb_state_t *state, ngx_mrb_code_t *code)
{
  FILE *mrb_file;
  struct mrb_parser_state *p;

  if (code->code_type == NGX_MRB_CODE_TYPE_FILE) {
    if ((mrb_file = fopen((char *)code->code.file, "r")) == NULL) {
      return NGX_ERROR;
    }
    code->ctx = mrbc_context_new(state->mrb);
    mrbc_filename(state->mrb, code->ctx, (char *)code->code.file);
    p = mrb_parse_file(state->mrb, mrb_file, code->ctx);
    fclose(mrb_file);
  } else {
    code->ctx = mrbc_context_new(state->mrb);
    mrbc_filename(state->mrb, code->ctx, "INLINE CODE");
    p = mrb_parse_string(state->mrb, (char *)code->code.string, code->ctx);
  }

  if (p == NULL) {
    return NGX_ERROR;
  }

  code->proc = mrb_generate_code(state->mrb, p);
  mrb_pool_close(p->pool);
  if (code->proc == NULL) {
    return NGX_ERROR;
  }

  if (code->code_type == NGX_MRB_CODE_TYPE_FILE) {
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "%s NOTICE %s:%d: compile info: code->code.file=(%s) code->cache=(%d)",
                       MODULE_NAME, __func__, __LINE__, code->code.file, code->cache);
  } else {
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "%s NOTICE %s:%d: compile info: "
                                              "code->code.string=(%s) code->cache=(%d)",
                       MODULE_NAME, __func__, __LINE__, code->code.string, code->cache);
  }

  return NGX_OK;
}

/*
// ngx_mruby mruby directive functions
*/

#if (NGX_HTTP_SSL)

static char *ngx_http_mruby_ssl_handshake_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_srv_conf_t *mscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_int_t rc;

  if (mscf->ssl_handshake_code != NGX_CONF_UNSET_PTR) {
    return "is duplicated";
  }

  /* share mrb_state of preinit */
  mscf->state = mmcf->state;

  value = cf->args->elts;

  code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    return NGX_CONF_ERROR;
  }
  mscf->ssl_handshake_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mscf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, MODULE_NAME " : mruby_ssl_handshake_inline mrb_string(%s) load failed",
                       value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}
#endif /* NGX_HTTP_SSL */

static char *ngx_http_mruby_init_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_int_t rc;

  if (mmcf->init_code != NGX_CONF_UNSET_PTR) {
    return "[Use either 'mruby_init' or 'mruby_init_code']";
  }

  value = cf->args->elts;

  code = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }
  if (cf->args->nelts == 3) {
    if (ngx_strcmp(value[2].data, "cache") == 0) {
      code->cache = ON;
    } else {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\", vaild parameter is only \"cache\"",
                         &value[2]);
      return NGX_CONF_ERROR;
    }
  }
  mmcf->init_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_init_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_int_t rc;

  if (mmcf->init_code != NGX_CONF_UNSET_PTR) {
    return "is duplicated";
  }

  value = cf->args->elts;

  code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    return NGX_CONF_ERROR;
  }
  mmcf->init_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_init_worker_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_int_t rc;

  if (mmcf->init_worker_code != NGX_CONF_UNSET_PTR) {
    return "[Use either 'mruby_init_worker' or 'mruby_init_worker_code'";
  }

  value = cf->args->elts;

  code = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }
  if (cf->args->nelts == 3) {
    if (ngx_strcmp(value[2].data, "cache") == 0) {
      code->cache = ON;
    } else {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\", vaild parameter is only \"cache\"",
                         &value[2]);
      return NGX_CONF_ERROR;
    }
  }
  mmcf->init_worker_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_init_worker_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_int_t rc;

  if (mmcf->init_worker_code != NGX_CONF_UNSET_PTR) {
    return "is duplicated";
  }

  value = cf->args->elts;

  code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    return NGX_CONF_ERROR;
  }
  mmcf->init_worker_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_exit_worker_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_int_t rc;

  if (mmcf->exit_worker_code != NGX_CONF_UNSET_PTR) {
    return "[Use either 'mruby_exit_worker' or 'mruby_exit_worker_code'";
  }

  value = cf->args->elts;

  code = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }
  if (cf->args->nelts == 3) {
    if (ngx_strcmp(value[2].data, "cache") == 0) {
      code->cache = ON;
    } else {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\", vaild parameter is only \"cache\"",
                         &value[2]);
      return NGX_CONF_ERROR;
    }
  }
  mmcf->exit_worker_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_exit_worker_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_int_t rc;

  if (mmcf->exit_worker_code != NGX_CONF_UNSET_PTR) {
    return "is duplicated";
  }

  value = cf->args->elts;

  code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    return NGX_CONF_ERROR;
  }
  mmcf->exit_worker_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_output_filter_error(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mruby_output_filter{,_code} was deleted from v1.17.2, you should use "
                                           "mruby_output_body_filter{,_code} for response body, or use "
                                           "mruby_output_header_filter{,_code} for response headers.");
  return NGX_CONF_ERROR;
}

static char *ngx_http_mruby_post_read_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf;
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_int_t rc;

  mlcf = conf;

  value = cf->args->elts;
  code = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }
  if (cf->args->nelts == 3) {
    if (ngx_strcmp(value[2].data, "cache") == 0) {
      code->cache = ON;
    } else {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\", vaild parameter is only \"cache\"",
                         &value[2]);
      return NGX_CONF_ERROR;
    }
  }
  mlcf->post_read_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_server_rewrite_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_http_mruby_loc_conf_t *mlcf;
  ngx_mrb_code_t *code;
  ngx_int_t rc;

  mlcf = conf;

  value = cf->args->elts;
  code = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }
  if (cf->args->nelts == 3) {
    if (ngx_strcmp(value[2].data, "cache") == 0) {
      code->cache = ON;
    } else {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\", vaild parameter is only \"cache\"",
                         &value[2]);
      return NGX_CONF_ERROR;
    }
  }
  mlcf->server_rewrite_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_rewrite_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  ngx_mrb_code_t *code;
  ngx_int_t rc;

  value = cf->args->elts;
  code = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }
  if (cf->args->nelts == 3) {
    if (ngx_strcmp(value[2].data, "cache") == 0) {
      code->cache = ON;
    } else {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\", vaild parameter is only \"cache\"",
                         &value[2]);
      return NGX_CONF_ERROR;
    }
  }
  mlcf->rewrite_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_access_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  ngx_mrb_code_t *code;
  ngx_int_t rc;

  value = cf->args->elts;
  code = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }
  if (cf->args->nelts == 3) {
    if (ngx_strcmp(value[2].data, "cache") == 0) {
      code->cache = ON;
    } else {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\", vaild parameter is only \"cache\"",
                         &value[2]);
      return NGX_CONF_ERROR;
    }
  }
  mlcf->access_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_content_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  ngx_mrb_code_t *code;
  ngx_int_t rc;

  value = cf->args->elts;
  code = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }
  if (cf->args->nelts == 3) {
    if (ngx_strcmp(value[2].data, "cache") == 0) {
      code->cache = ON;
    } else {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\", vaild parameter is only \"cache\"",
                         &value[2]);
      return NGX_CONF_ERROR;
    }
  }
  mlcf->content_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_log_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  ngx_mrb_code_t *code;
  ngx_int_t rc;

  value = cf->args->elts;
  code = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }
  if (cf->args->nelts == 3) {
    if (ngx_strcmp(value[2].data, "cache") == 0) {
      code->cache = ON;
    } else {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\", vaild parameter is only \"cache\"",
                         &value[2]);
      return NGX_CONF_ERROR;
    }
  }
  mlcf->log_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_post_read_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  ngx_int_t rc;

  value = cf->args->elts;
  code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    return NGX_CONF_ERROR;
  }
  mlcf->post_read_inline_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_server_rewrite_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  ngx_int_t rc;

  value = cf->args->elts;
  code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    return NGX_CONF_ERROR;
  }
  mlcf->server_rewrite_inline_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_rewrite_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  ngx_int_t rc;

  value = cf->args->elts;
  code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    return NGX_CONF_ERROR;
  }
  mlcf->rewrite_inline_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_access_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  ngx_int_t rc;

  value = cf->args->elts;
  code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    return NGX_CONF_ERROR;
  }
  mlcf->access_inline_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_content_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  ngx_int_t rc;

  value = cf->args->elts;
  code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    return NGX_CONF_ERROR;
  }
  mlcf->content_inline_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_log_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  ngx_int_t rc;

  value = cf->args->elts;
  code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    return NGX_CONF_ERROR;
  }
  mlcf->log_inline_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_body_filter_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  ngx_mrb_code_t *code;
  ngx_int_t rc;

  value = cf->args->elts;
  code = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }
  if (cf->args->nelts == 3) {
    if (ngx_strcmp(value[2].data, "cache") == 0) {
      code->cache = ON;
    } else {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\", vaild parameter is only \"cache\"",
                         &value[2]);
      return NGX_CONF_ERROR;
    }
  }
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }
  mlcf->body_filter_code = code;
  mmcf->enabled_body_filter = 1;
  mmcf->enabled_header_filter = 1;
  mlcf->body_filter_handler = cmd->post;

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_header_filter_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  ngx_mrb_code_t *code;
  ngx_int_t rc;

  value = cf->args->elts;
  code = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }
  if (cf->args->nelts == 3) {
    if (ngx_strcmp(value[2].data, "cache") == 0) {
      code->cache = ON;
    } else {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\", vaild parameter is only \"cache\"",
                         &value[2]);
      return NGX_CONF_ERROR;
    }
  }
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    return NGX_CONF_ERROR;
  }
  mlcf->header_filter_code = code;
  mmcf->enabled_header_filter = 1;
  mlcf->header_filter_handler = cmd->post;

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_body_filter_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  ngx_int_t rc;

  value = cf->args->elts;
  code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    return NGX_CONF_ERROR;
  }
  mlcf->body_filter_inline_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }
  mmcf->enabled_body_filter = 1;
  mmcf->enabled_header_filter = 1;
  mlcf->body_filter_handler = cmd->post;

  return NGX_CONF_OK;
}

static char *ngx_http_mruby_header_filter_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_http_mruby_loc_conf_t *mlcf = conf;
  ngx_int_t rc;

  value = cf->args->elts;
  code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
  if (code == NGX_CONF_UNSET_PTR) {
    return NGX_CONF_ERROR;
  }
  mlcf->header_filter_inline_code = code;
  rc = ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }
  mmcf->enabled_header_filter = 1;
  mlcf->header_filter_handler = cmd->post;

  return NGX_CONF_OK;
}

#if defined(NDK) && NDK

static char *ngx_http_mruby_set_inner(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, code_type_t type)
{
  ngx_str_t target;
  ngx_str_t *value;
  ndk_set_var_t filter;
  ngx_http_mruby_set_var_data_t *filter_data;
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
  ngx_int_t rc;

  value = cf->args->elts;
  target = value[1];

  filter.type = NDK_SET_VAR_MULTI_VALUE_DATA;
  filter.func = cmd->post;
  filter.size = cf->args->nelts - 3;

  filter_data = ngx_pcalloc(cf->pool, sizeof(ngx_http_mruby_set_var_data_t));
  if (filter_data == NULL) {
    return NGX_CONF_ERROR;
  }

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
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\", vaild parameter is only \"cache\"",
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
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
    } else {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    }
    return NGX_CONF_ERROR;
  }
  if (filter_data->code == NGX_CONF_UNSET_PTR) {
    if (type == NGX_MRB_CODE_TYPE_FILE) {
      ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "failed to load mruby script: %s %s:%d", filter_data->script.data,
                         __FUNCTION__, __LINE__, target.data, filter_data->script.data);
    }
    return NGX_CONF_ERROR;
  }

  filter.data = filter_data;
  ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "%s NOTICE %s:%d: target variable=(%s)", MODULE_NAME, __FUNCTION__,
                     __LINE__, target.data);

  return ndk_set_var_multi_value_core(cf, &target, &value[3], &filter);
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

#define NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(handler_name, code)                                                        \
  static ngx_int_t ngx_http_mruby_##handler_name##_handler(ngx_http_request_t *r)                                      \
  {                                                                                                                    \
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);                        \
    ngx_http_mruby_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);                          \
    if (mmcf->state == NGX_CONF_UNSET_PTR) {                                                                           \
      return NGX_DECLINED;                                                                                             \
    }                                                                                                                  \
    if (code == NGX_CONF_UNSET_PTR) {                                                                                  \
      return NGX_DECLINED;                                                                                             \
    }                                                                                                                  \
    if (!code->cache) {                                                                                                \
      NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(mlcf->cached, mmcf->state, code, ngx_http_mruby_state_reinit_from_file);    \
    }                                                                                                                  \
    return ngx_mrb_run(r, mmcf->state, code, mlcf->cached, NULL);                                                      \
  }

NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(post_read, mlcf->post_read_code)
NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(server_rewrite, mlcf->server_rewrite_code)
NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(rewrite, mlcf->rewrite_code)
NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(access, mlcf->access_code)
// NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(content,    mlcf->content_code)
NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(log, mlcf->log_code)

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
  if (!code->cache) {
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(mlcf->cached, mmcf->state, code, ngx_http_mruby_state_reinit_from_file);
  }
  return ngx_mrb_run(r, mmcf->state, code, mlcf->cached, NULL);
}

#define NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(handler_name, code)                                                 \
  static ngx_int_t ngx_http_mruby_##handler_name##_inline_handler(ngx_http_request_t *r)                               \
  {                                                                                                                    \
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);                        \
    ngx_http_mruby_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);                          \
    return ngx_mrb_run(r, mmcf->state, code, 1, NULL);                                                                 \
  }

NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(post_read, mlcf->post_read_inline_code)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(server_rewrite, mlcf->server_rewrite_inline_code)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(rewrite, mlcf->rewrite_inline_code)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(access, mlcf->access_inline_code)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(content, mlcf->content_inline_code)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(log, mlcf->log_inline_code)

#if defined(NDK) && NDK
static ngx_int_t ngx_http_mruby_set_handler(ngx_http_request_t *r, ngx_str_t *val, ngx_http_variable_value_t *v,
                                            void *data)
{
  ngx_http_mruby_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
  ngx_http_mruby_set_var_data_t *filter_data;

  filter_data = data;

  if (filter_data->state == NGX_CONF_UNSET_PTR) {
    return NGX_DECLINED;
  }

  if (filter_data->code == NGX_CONF_UNSET_PTR) {
    return NGX_DECLINED;
  }

  if (!filter_data->code->cache) {
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(mlcf->cached, filter_data->state, filter_data->code,
                                         ngx_http_mruby_state_reinit_from_file);
  }

  return ngx_mrb_run(r, filter_data->state, filter_data->code, mlcf->cached, val);
}

static ngx_int_t ngx_http_mruby_set_inline_handler(ngx_http_request_t *r, ngx_str_t *val, ngx_http_variable_value_t *v,
                                                   void *data)
{
  ngx_http_mruby_set_var_data_t *filter_data;
  filter_data = data;
  return ngx_mrb_run(r, filter_data->state, filter_data->code, 1, val);
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

static ngx_int_t ngx_http_mruby_body_filter_handler(ngx_http_request_t *r, ngx_chain_t *in)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
  ngx_http_mruby_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);
  ngx_int_t rc;
  ngx_chain_t out;
  ngx_buf_t *b;

  if ((rc = ngx_http_mruby_read_body(r, in, ctx)) != NGX_OK) {
    if (rc == NGX_AGAIN) {
      return NGX_OK;
    }
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to read body %s:%d", __FUNCTION__, __LINE__);
    return NGX_ERROR;
  }

  r->connection->buffered &= ~0x08;

  if (!mlcf->body_filter_code->cache) {
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(mlcf->cached, mmcf->state, mlcf->body_filter_code,
                                         ngx_http_mruby_state_reinit_from_file);
  }

  rc = ngx_mrb_run(r, mmcf->state, mlcf->body_filter_code, mlcf->cached, NULL);
  if (rc == NGX_ERROR) {
    return NGX_ERROR;
  }

  b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
  if (b == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory from r->pool %s:%d", __FUNCTION__,
                  __LINE__);
    return NGX_ERROR;
  }

  b->pos = ctx->body;
  b->last = ctx->body + ctx->body_length;
  b->memory = 1;
  b->last_buf = 1;

  out.buf = b;
  out.next = NULL;

  r->headers_out.content_length_n = b->last - b->pos;
  rc = ngx_http_next_header_filter(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    return NGX_ERROR;
  }
  return ngx_http_next_body_filter(r, &out);
}

static ngx_int_t ngx_http_mruby_body_filter_inline_handler(ngx_http_request_t *r, ngx_chain_t *in)
{
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
  ngx_http_mruby_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);
  ngx_int_t rc;
  ngx_chain_t out;
  ngx_buf_t *b;

  if ((rc = ngx_http_mruby_read_body(r, in, ctx)) != NGX_OK) {
    if (rc == NGX_AGAIN) {
      return NGX_OK;
    }
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to read body %s:%d", __FUNCTION__, __LINE__);
    return NGX_ERROR;
  }

  r->connection->buffered &= ~0x08;

  rc = ngx_mrb_run(r, mmcf->state, mlcf->body_filter_inline_code, mlcf->cached, NULL);
  if (rc == NGX_ERROR) {
    return NGX_ERROR;
  }

  b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
  if (b == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory from r->pool %s:%d", __FUNCTION__,
                  __LINE__);
    return NGX_ERROR;
  }

  b->pos = ctx->body;
  b->last = ctx->body + ctx->body_length;
  b->memory = 1;
  b->last_buf = 1;

  out.buf = b;
  out.next = NULL;

  r->headers_out.content_length_n = b->last - b->pos;
  rc = ngx_http_next_header_filter(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    return NGX_ERROR;
  }
  return ngx_http_next_body_filter(r, &out);
}

static ngx_int_t ngx_http_mruby_header_filter_handler(ngx_http_request_t *r, ngx_chain_t *in)
{
  ngx_int_t rc;
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);

  if (!mlcf->header_filter_code->cache) {
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(mlcf->cached, mmcf->state, mlcf->header_filter_code,
                                         ngx_http_mruby_state_reinit_from_file);
  }

  rc = ngx_mrb_run(r, mmcf->state, mlcf->header_filter_code, mlcf->cached, NULL);
  if (rc == NGX_ERROR) {
    return NGX_ERROR;
  }

  rc = ngx_http_next_header_filter(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    return NGX_ERROR;
  }
  return rc;
}

static ngx_int_t ngx_http_mruby_header_filter_inline_handler(ngx_http_request_t *r, ngx_chain_t *in)
{
  ngx_int_t rc;
  ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
  ngx_http_mruby_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);

  rc = ngx_mrb_run(r, mmcf->state, mlcf->header_filter_inline_code, mlcf->cached, NULL);
  if (rc == NGX_ERROR) {
    return NGX_ERROR;
  }

  rc = ngx_http_next_header_filter(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    return NGX_ERROR;
  }
  return rc;
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

  ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);
  if (ctx == NULL) {
    if ((ctx = ngx_pcalloc(r->pool, sizeof(*ctx))) == NULL) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory from r->pool %s:%d", __FUNCTION__,
                    __LINE__);
      return NGX_ERROR;
    }
    ctx->body = NULL;
    ngx_http_set_ctx(r, ctx, ngx_http_mruby_module);
  }
  ctx->body_length = r->headers_out.content_length_n;

  cln = ngx_pool_cleanup_add(r->pool, 0);
  if (cln == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory from r->pool %s:%d", __FUNCTION__,
                  __LINE__);
    return NGX_ERROR;
  }
  cln->handler = ngx_http_mruby_filter_cleanup;
  cln->data = ctx;

  if (mlcf->header_filter_handler != NULL) {
    rc = mlcf->header_filter_handler(r);
    if (rc != NGX_OK) {
      return NGX_ERROR;
    }
  }

  ctx->body_length = r->headers_out.content_length_n;

  return NGX_OK;
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

  ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);
  if (ctx == NULL) {
    if ((ctx = ngx_pcalloc(r->pool, sizeof(*ctx))) == NULL) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory from r->pool %s:%d", __FUNCTION__,
                    __LINE__);
      return NGX_ERROR;
    }
    ctx->body = NULL;
    ngx_http_set_ctx(r, ctx, ngx_http_mruby_module);
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
  if (rc != NGX_OK) {
    return NGX_ERROR;
  }
  return NGX_OK;
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
    size = (rest < size) ? rest : size;
    p = ngx_cpymem(p, b->pos, size);
    b->pos += size;
    if (b->last_buf) {
      ctx->last = p;
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

  /* read certficate data from memory buffer */
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
    return NGX_ERROR;
  }

  x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
  if (x509 == NULL) {
    BIO_free(bio);
    return NGX_ERROR;
  }

  SSL_certs_clear(ssl_conn);
  if (SSL_use_certificate(ssl_conn, x509) == 0) {
    X509_free(x509);
    BIO_free(bio);
    return NGX_ERROR;
  }

#if 0
    if (SSL_set_ex_data(ssl_conn, ngx_ssl_certificate_index, x509) == 0) {
        X509_free(x509);
        BIO_free(bio);
        return NGX_ERROR;
    }
#endif

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

      BIO_free(bio);
      return NGX_ERROR;
    }

    if (SSL_add0_chain_cert(ssl_conn, x509) == 0) {
      X509_free(x509);
      BIO_free(bio);
      return NGX_ERROR;
    }
  }

  BIO_free(bio);
  bio = NULL;

  if (SSL_use_PrivateKey_file(ssl_conn, (char *)key->data, SSL_FILETYPE_PEM) != 1) {
    return NGX_ERROR;
  }

  return NGX_OK;
}

#endif /* NGX_HTTP_SSL */

#if (NGX_HTTP_SSL) && OPENSSL_VERSION_NUMBER >= 0x1000205fL

static int ngx_http_mruby_ssl_cert_handler(ngx_ssl_conn_t *ssl_conn, void *data)
{
  ngx_connection_t *c;
  ngx_http_connection_t *hc;
  const char *servername;
  ngx_http_mruby_srv_conf_t *mscf;
  ngx_str_t host;
  mrb_int ai;
  mrb_state *mrb;

  c = ngx_ssl_get_connection(ssl_conn);
  if (c == NULL) {
    return 0;
  }

  hc = c->data;
  if (NULL == hc) {
    ngx_log_error(NGX_LOG_ERR, c->log, 0, MODULE_NAME " : mruby ssl handler: ssl connection data hc NULL");
    return 0;
  }

  servername = SSL_get_servername(ssl_conn, TLSEXT_NAMETYPE_host_name);
  if (servername == NULL) {
    ngx_log_error(NGX_LOG_DEBUG, c->log, 0, MODULE_NAME " : mruby ssl handler: SSL server name NULL");
    return 1;
  }

  host.len = ngx_strlen(servername);
  if (host.len == 0) {
    ngx_log_error(NGX_LOG_DEBUG, c->log, 0, MODULE_NAME " : mruby ssl handler: host len == 0");
    return 1;
  }
  host.data = (u_char *)servername;
  ngx_log_error(NGX_LOG_DEBUG, c->log, 0, MODULE_NAME " : mruby ssl handler: servername \"%V\"", &host);

  mscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_mruby_module);
  if (NULL == mscf) {
    ngx_log_error(NGX_LOG_ERR, c->log, 0, MODULE_NAME " : mruby ssl handler: mscf NULL");
    return 1;
  }

  if (mscf->ssl_handshake_code == NGX_CONF_UNSET_PTR) {
    ngx_log_error(NGX_LOG_ERR, c->log, 0, MODULE_NAME " : mruby ssl handler: unexpected error, mruby code not found");
    return 1;
  }

  mscf->servername = &host;
  mrb = mscf->state->mrb;
  mrb->ud = mscf;
  ai = mrb_gc_arena_save(mrb);
  mrb_run(mrb, mscf->ssl_handshake_code->proc, mrb_top_self(mrb));

  if (mrb->exc) {
    struct RString *str;
    char *err_out;
    mrb_value obj = mrb_funcall(mrb, mrb_obj_value(mrb->exc), "inspect", 0);
    if (mrb_type(obj) == MRB_TT_STRING) {
      str = mrb_str_ptr(obj);
      err_out = str->as.heap.ptr;
      ngx_log_error(NGX_LOG_ERR, c->log, 0,
                    MODULE_NAME " : mrb_run failed: return 500 HTTP status code to client: error: %s", err_out);
    }
    ngx_mrb_state_clean(NULL, mscf->state);
    mrb_gc_arena_restore(mrb, ai);
    return 0;
  }

  ngx_mrb_state_clean(NULL, mscf->state);
  mrb_gc_arena_restore(mrb, ai);

  if (mscf->cert_data.len == 0 || mscf->cert_key_data.len == 0) {
    if (mscf->cert_path.len == 0 || mscf->cert_key_path.len == 0) {
      ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
                    MODULE_NAME " : mruby ssl handler: cert or cert key not exists or not read");
      return 1;
    }

    errno = 0;
    if (access((const char *)mscf->cert_path.data, F_OK | R_OK) != 0) {
      if (errno == EACCES) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, MODULE_NAME " : mruby ssl handler: cert [%V] permission denied",
                      &mscf->cert_path);
      } else {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, MODULE_NAME " : mruby ssl handler: cert [%V] not exists or not read",
                      &mscf->cert_path);
      }
      return 0;
    }
    errno = 0;
    if (access((const char *)mscf->cert_key_path.data, F_OK | R_OK) != 0) {
      if (errno == EACCES) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, MODULE_NAME " : mruby ssl handler: cert_key [%V] permission denied",
                      &mscf->cert_key_path);
      } else {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, MODULE_NAME " : mruby ssl handler: cert_key [%V] not exists or not read",
                      &mscf->cert_key_path);
      }
      return 0;
    }

    ngx_log_error(NGX_LOG_DEBUG, c->log, 0, MODULE_NAME " : mruby ssl handler: changing certficate to cert=%V key=%V",
                  &mscf->cert_path, &mscf->cert_key_path);
    ngx_http_mruby_set_der_certificate(ssl_conn, &mscf->cert_path, &mscf->cert_key_path);
  } else {
    ngx_log_error(NGX_LOG_DEBUG, c->log, 0, MODULE_NAME " : mruby ssl handler: changing certficate by mem buffer");
    ngx_http_mruby_set_der_certificate_data(ssl_conn, &mscf->cert_data, &mscf->cert_key_data);
  }

  return 1;
}
#endif /* NGX_HTTP_SSL */
