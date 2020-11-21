/*
// ngx_stream_mruby_module.c - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_stream_mruby_module.h"
#include "ngx_stream_mruby_core.h"
#include "ngx_stream_mruby_async.h"

#include "ngx_stream_mruby_init.h"

#include "mruby/string.h"

#define NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mrb, code)                                                                    \
  if (code != NGX_CONF_UNSET_PTR && mrb && (code)->ctx) {                                                              \
    mrbc_context_free(mrb, (code)->ctx);                                                                               \
    (code)->ctx = NULL;                                                                                                \
  }

/* stream session mruby handler */
static ngx_int_t ngx_stream_mruby_handler(ngx_stream_session_t *s);

/* stream session mruby directive functions */
static char *ngx_stream_mruby_build_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_stream_mruby_build_code(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_stream_mruby_server_context_code(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* mruby core functions for compile */
static void ngx_stream_mrb_state_clean(mrb_state *mrb);
static ngx_mrb_code_t *ngx_stream_mruby_mrb_code_from_file(ngx_pool_t *pool, ngx_str_t *code_s);
static ngx_mrb_code_t *ngx_stream_mruby_mrb_code_from_string(ngx_pool_t *pool, ngx_str_t *code_s);
static ngx_int_t ngx_stream_mruby_shared_state_compile(ngx_conf_t *cf, mrb_state *mrb, ngx_mrb_code_t *code);
static ngx_int_t ngx_stream_mrb_run_cycle(ngx_cycle_t *cycle, mrb_state *mrb, ngx_mrb_code_t *code);
// static ngx_int_t ngx_stream_mrb_run_conf(ngx_conf_t *cf, mrb_state *mrb, ngx_mrb_code_t *code);

/* mruby raise functions */
static void ngx_stream_mrb_raise_cycle_error(mrb_state *mrb, mrb_value obj, ngx_cycle_t *cycle);
// static void ngx_stream_mrb_raise_conf_error(mrb_state *mrb, mrb_value obj, ngx_conf_t *cf);

/* ngx_mruby stream module init and exit handlers */
static ngx_int_t ngx_stream_mruby_init_module(ngx_cycle_t *cycle);
static ngx_int_t ngx_stream_mruby_init_worker(ngx_cycle_t *cycle);
static void ngx_stream_mruby_exit_worker(ngx_cycle_t *cycle);

/* ngx_mruby stream module init and exit directive functions */
static char *ngx_stream_mruby_init_build_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_stream_mruby_init_build_code(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_stream_mruby_init_worker_build_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_stream_mruby_init_worker_build_code(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_stream_mruby_exit_worker_build_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_stream_mruby_exit_worker_build_code(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* setup main and srv configuration */
static void *ngx_stream_mruby_create_main_conf(ngx_conf_t *cf);
static char *ngx_stream_mruby_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_stream_mruby_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_mruby_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

/* ngx_mruby stream init function after creating main and srv configuration */
static ngx_int_t ngx_stream_mruby_init(ngx_conf_t *cf);

static ngx_command_t ngx_stream_mruby_commands[] = {

    {ngx_string("mruby_stream_init"), NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE1, ngx_stream_mruby_init_build_file,
     NGX_STREAM_MAIN_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_stream_init_code"), NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE1, ngx_stream_mruby_init_build_code,
     NGX_STREAM_MAIN_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_stream_init_worker"), NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_stream_mruby_init_worker_build_file, NGX_STREAM_MAIN_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_stream_init_worker_code"), NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_stream_mruby_init_worker_build_code, NGX_STREAM_MAIN_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_stream_exit_worker"), NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_stream_mruby_exit_worker_build_file, NGX_STREAM_MAIN_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_stream_exit_worker_code"), NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_stream_mruby_exit_worker_build_code, NGX_STREAM_MAIN_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_stream"), NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
     ngx_stream_mruby_build_file, NGX_STREAM_SRV_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_stream_code"), NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
     ngx_stream_mruby_build_code, NGX_STREAM_SRV_CONF_OFFSET, 0, NULL},

    {ngx_string("mruby_stream_server_context_code"), NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
     ngx_stream_mruby_server_context_code, NGX_STREAM_SRV_CONF_OFFSET, 0, NULL},

    ngx_null_command};

#if (nginx_version > 1011001)
static ngx_stream_module_t ngx_stream_mruby_module_ctx = {
    NULL,                  /* preconfiguration */
    ngx_stream_mruby_init, /* postconfiguration */

    ngx_stream_mruby_create_main_conf, /* create main configuration */
    ngx_stream_mruby_init_main_conf,   /* init main configuration */

    ngx_stream_mruby_create_srv_conf, /* create server configuration */
    ngx_stream_mruby_merge_srv_conf   /* merge server configuration */
};
#else
static ngx_stream_module_t ngx_stream_mruby_module_ctx = {
    ngx_stream_mruby_init, /* postconfiguration */

    ngx_stream_mruby_create_main_conf, /* create main configuration */
    ngx_stream_mruby_init_main_conf,   /* init main configuration */

    ngx_stream_mruby_create_srv_conf, /* create server configuration */
    ngx_stream_mruby_merge_srv_conf   /* merge server configuration */
};
#endif

ngx_module_t ngx_stream_mruby_module = {NGX_MODULE_V1,
                                        &ngx_stream_mruby_module_ctx, /* module context */
                                        ngx_stream_mruby_commands,    /* module directives */
                                        NGX_STREAM_MODULE,            /* module type */
                                        NULL,                         /* init master */
                                        ngx_stream_mruby_init_module, /* init module */
                                        ngx_stream_mruby_init_worker, /* init process */
                                        NULL,                         /* init thread */
                                        NULL,                         /* exit thread */
                                        ngx_stream_mruby_exit_worker, /* exit process */
                                        NULL,                         /* exit master */
                                        NGX_MODULE_V1_PADDING};

static mrb_state *ngx_stream_mrb_state(ngx_stream_session_t *s)
{
  return ((ngx_stream_mruby_main_conf_t *)ngx_stream_get_module_main_conf(s, ngx_stream_mruby_module))->ctx->mrb;
}

static mrb_state *ngx_stream_mrb_state_conf(ngx_conf_t *cf)
{
  return ((ngx_stream_mruby_main_conf_t *)ngx_stream_conf_get_module_main_conf(cf, ngx_stream_mruby_module))->ctx->mrb;
}

static void ngx_stream_mruby_cleanup(void *data)
{
  ngx_stream_mruby_main_conf_t *mmcf = data;

  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mmcf->ctx->mrb, mmcf->init_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mmcf->ctx->mrb, mmcf->init_worker_code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mmcf->ctx->mrb, mmcf->exit_worker_code);

  mrb_close(mmcf->ctx->mrb);
}

static void *ngx_stream_mruby_create_main_conf(ngx_conf_t *cf)
{
  ngx_stream_mruby_main_conf_t *mmcf;
  ngx_stream_mruby_internal_ctx_t *ictx;
  ngx_pool_cleanup_t *cln;

  cln = ngx_pool_cleanup_add(cf->pool, 0);
  if (cln == NULL) {
    return NULL;
  }

  mmcf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_mruby_main_conf_t));
  if (mmcf == NULL) {
    return NULL;
  }
  mmcf->ctx = ngx_pcalloc(cf->pool, sizeof(ngx_stream_mruby_conf_ctx_t));
  if (mmcf->ctx == NULL) {
    return NULL;
  }

  mmcf->init_code = NGX_CONF_UNSET_PTR;
  mmcf->init_worker_code = NGX_CONF_UNSET_PTR;
  mmcf->exit_worker_code = NGX_CONF_UNSET_PTR;

  mmcf->ctx->mrb = mrb_open();
  if (mmcf->ctx->mrb == NULL)
    return NULL;
  ngx_stream_mrb_class_init(mmcf->ctx->mrb);

  cln->handler = ngx_stream_mruby_cleanup;
  cln->data = mmcf;

  ictx = ngx_pcalloc(cf->pool, sizeof(ngx_stream_mruby_internal_ctx_t));
  if (ictx == NULL) {
    return NULL;
  }
  ictx->s = NULL;
  ictx->stream_status = NGX_DECLINED;
  mmcf->ctx->mrb->ud = ictx;

  return mmcf;
}

static char *ngx_stream_mruby_init_main_conf(ngx_conf_t *cf, void *conf)
{
  return NGX_CONF_OK;
}

/* create directive template */

static void ngx_stream_mruby_srv_conf_cleanup(void *data)
{
  ngx_stream_mruby_srv_conf_t *mscf = data;

  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mscf->ctx->mrb, mscf->code);
}

static void *ngx_stream_mruby_create_srv_conf(ngx_conf_t *cf)
{
  ngx_stream_mruby_srv_conf_t *mscf;
  ngx_pool_cleanup_t *cln;

  cln = ngx_pool_cleanup_add(cf->pool, 0);
  if (cln == NULL) {
    return NULL;
  }

  mscf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_mruby_srv_conf_t));
  if (mscf == NULL) {
    return NULL;
  }
  mscf->ctx = ngx_pcalloc(cf->pool, sizeof(ngx_stream_mruby_conf_ctx_t));
  if (mscf->ctx == NULL) {
    return NULL;
  }

  mscf->code = NGX_CONF_UNSET_PTR;

  cln->handler = ngx_stream_mruby_srv_conf_cleanup;
  cln->data = mscf;

  return mscf;
}

/* merge directive configuration */
static char *ngx_stream_mruby_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_stream_mruby_srv_conf_t *prev = parent;
  ngx_stream_mruby_srv_conf_t *conf = child;

  if (conf->code == NGX_CONF_UNSET_PTR) {
    conf->code = prev->code;
  }

  return NGX_CONF_OK;
}

/* raise functions */
static void ngx_stream_mruby_raise_conf_error(mrb_state *mrb, mrb_value obj, ngx_conf_t *cf)
{
  obj = mrb_funcall(mrb, obj, "inspect", 0);
  if (mrb_type(obj) == MRB_TT_STRING) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_run failed: ngx_mruby stream module configuration failed: error: %*s",
                       RSTRING_LEN(obj), RSTRING_PTR(obj));
  }
}

void ngx_stream_mruby_raise_error(mrb_state *mrb, mrb_value obj, ngx_stream_session_t *s)
{
  obj = mrb_funcall(mrb, obj, "inspect", 0);
  if (mrb_type(obj) == MRB_TT_STRING) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "mrb_run failed: return NGX_ABORT to client: error: %*s",
                  RSTRING_LEN(obj), RSTRING_PTR(obj));
  }
}

static void ngx_stream_mrb_raise_cycle_error(mrb_state *mrb, mrb_value obj, ngx_cycle_t *cycle)
{
  obj = mrb_funcall(mrb, obj, "inspect", 0);
  if (mrb_type(obj) == MRB_TT_STRING) {
    ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "mrb_run failed. error: %*s", RSTRING_LEN(obj), RSTRING_PTR(obj));
  }
}

static ngx_int_t ngx_stream_mruby_init_module(ngx_cycle_t *cycle)
{
  ngx_stream_mruby_main_conf_t *mmcf = ngx_stream_cycle_get_module_main_conf(cycle, ngx_stream_mruby_module);

  if (mmcf == NULL)
    return NGX_OK;

  if (mmcf->init_code != NGX_CONF_UNSET_PTR)
    return ngx_stream_mrb_run_cycle(cycle, mmcf->ctx->mrb, mmcf->init_code);

  return NGX_OK;
}

static ngx_int_t ngx_stream_mruby_init_worker(ngx_cycle_t *cycle)
{
  ngx_stream_mruby_main_conf_t *mmcf = ngx_stream_cycle_get_module_main_conf(cycle, ngx_stream_mruby_module);

  if (mmcf == NULL)
    return NGX_OK;

  if (mmcf->init_worker_code != NGX_CONF_UNSET_PTR)
    return ngx_stream_mrb_run_cycle(cycle, mmcf->ctx->mrb, mmcf->init_worker_code);

  return NGX_OK;
}

static void ngx_stream_mruby_exit_worker(ngx_cycle_t *cycle)
{
  ngx_stream_mruby_main_conf_t *mmcf = ngx_stream_cycle_get_module_main_conf(cycle, ngx_stream_mruby_module);

  if (mmcf == NULL)
    return;

  if (mmcf->exit_worker_code != NGX_CONF_UNSET_PTR)
    ngx_stream_mrb_run_cycle(cycle, mmcf->ctx->mrb, mmcf->exit_worker_code);
}

/* ngx_mruby stream core functions */
static void ngx_stream_mrb_state_clean(mrb_state *mrb)
{
  mrb->exc = 0;
}

static ngx_mrb_code_t *ngx_stream_mruby_mrb_code_from_file(ngx_pool_t *pool, ngx_str_t *code_file_path)
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

  return code;
}

static ngx_mrb_code_t *ngx_stream_mruby_mrb_code_from_string(ngx_pool_t *pool, ngx_str_t *code_s)
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

  return code;
}

static ngx_int_t ngx_stream_mruby_shared_state_compile(ngx_conf_t *cf, mrb_state *mrb, ngx_mrb_code_t *code)
{
  FILE *mrb_file;
  struct mrb_parser_state *p;

  if (code->code_type == NGX_MRB_CODE_TYPE_FILE) {
    if ((mrb_file = fopen((char *)code->code.file, "r")) == NULL) {
      return NGX_ERROR;
    }
    NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mrb, code);
    code->ctx = mrbc_context_new(mrb);
    mrbc_filename(mrb, code->ctx, (char *)code->code.file);
    p = mrb_parse_file(mrb, mrb_file, code->ctx);
    fclose(mrb_file);
  } else {
    NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mrb, code);
    code->ctx = mrbc_context_new(mrb);
    mrbc_filename(mrb, code->ctx, "INLINE CODE");
    p = mrb_parse_string(mrb, (char *)code->code.string, code->ctx);
  }

  if (p == NULL || (0 < p->nerr)) {
    return NGX_ERROR;
  }

  code->proc = mrb_generate_code(mrb, p);
  mrb_pool_close(p->pool);
  if (code->proc == NULL) {
    return NGX_ERROR;
  }

  if (code->code_type == NGX_MRB_CODE_TYPE_FILE) {
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "%s NOTICE %s:%d: compile info: code->code.file=(%s)", MODULE_NAME,
                       __func__, __LINE__, code->code.file);
  } else {
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                       "%s NOTICE %s:%d: compile info: "
                       "code->code.string=(%s)",
                       MODULE_NAME, __func__, __LINE__, code->code.string);
  }

  return NGX_OK;
}

static ngx_int_t ngx_stream_mrb_run_cycle(ngx_cycle_t *cycle, mrb_state *mrb, ngx_mrb_code_t *code)
{
  mrb_int ai = mrb_gc_arena_save(mrb);

  mrb_toplevel_run(mrb, code->proc);
  if (mrb->exc) {
    ngx_stream_mrb_raise_cycle_error(mrb, mrb_obj_value(mrb->exc), cycle);
    mrb_gc_arena_restore(mrb, ai);
    return NGX_ERROR;
  }

  mrb_gc_arena_restore(mrb, ai);
  return NGX_OK;
}

/* ngx_mruby stream init or exit directive functions */
static char *ngx_stream_mruby_init_build_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_int_t rc;
  ngx_stream_mruby_main_conf_t *mmcf = conf;
  ngx_str_t *value = cf->args->elts;
  ngx_mrb_code_t *code = ngx_stream_mruby_mrb_code_from_file(cf->pool, &value[1]);

  if (code == NGX_CONF_UNSET_PTR)
    return NGX_CONF_ERROR;

  rc = ngx_stream_mruby_shared_state_compile(cf, mmcf->ctx->mrb, code);
  mmcf->init_code = code;

  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_stream_mruby_init_build_code(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_int_t rc;
  ngx_stream_mruby_main_conf_t *mmcf = conf;
  ngx_str_t *value = cf->args->elts;
  ngx_mrb_code_t *code = ngx_stream_mruby_mrb_code_from_string(cf->pool, &value[1]);

  if (code == NGX_CONF_UNSET_PTR)
    return NGX_CONF_ERROR;

  rc = ngx_stream_mruby_shared_state_compile(cf, mmcf->ctx->mrb, code);
  mmcf->init_code = code;

  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_stream_mruby_init_worker_build_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_int_t rc;
  ngx_stream_mruby_main_conf_t *mmcf = conf;
  ngx_str_t *value = cf->args->elts;
  ngx_mrb_code_t *code = ngx_stream_mruby_mrb_code_from_file(cf->pool, &value[1]);

  if (code == NGX_CONF_UNSET_PTR)
    return NGX_CONF_ERROR;

  rc = ngx_stream_mruby_shared_state_compile(cf, mmcf->ctx->mrb, code);
  mmcf->init_worker_code = code;

  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_stream_mruby_init_worker_build_code(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_int_t rc;
  ngx_stream_mruby_main_conf_t *mmcf = conf;
  ngx_str_t *value = cf->args->elts;
  ngx_mrb_code_t *code = ngx_stream_mruby_mrb_code_from_string(cf->pool, &value[1]);

  if (code == NGX_CONF_UNSET_PTR)
    return NGX_CONF_ERROR;

  rc = ngx_stream_mruby_shared_state_compile(cf, mmcf->ctx->mrb, code);
  mmcf->init_worker_code = code;

  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_stream_mruby_exit_worker_build_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_int_t rc;
  ngx_stream_mruby_main_conf_t *mmcf = conf;
  ngx_str_t *value = cf->args->elts;
  ngx_mrb_code_t *code = ngx_stream_mruby_mrb_code_from_file(cf->pool, &value[1]);

  if (code == NGX_CONF_UNSET_PTR)
    return NGX_CONF_ERROR;

  rc = ngx_stream_mruby_shared_state_compile(cf, mmcf->ctx->mrb, code);
  mmcf->exit_worker_code = code;

  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_stream_mruby_exit_worker_build_code(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_int_t rc;
  ngx_stream_mruby_main_conf_t *mmcf = conf;
  ngx_str_t *value = cf->args->elts;
  ngx_mrb_code_t *code = ngx_stream_mruby_mrb_code_from_string(cf->pool, &value[1]);

  if (code == NGX_CONF_UNSET_PTR)
    return NGX_CONF_ERROR;

  rc = ngx_stream_mruby_shared_state_compile(cf, mmcf->ctx->mrb, code);
  mmcf->exit_worker_code = code;

  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

/* set directive values from file*/
static char *ngx_stream_mruby_build_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  mrb_state *mrb = ngx_stream_mrb_state_conf(cf);
  ngx_stream_mruby_srv_conf_t *mscf = conf;
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_int_t rc;

  mscf->ctx->mrb = mrb;

  value = cf->args->elts;
  code = ngx_stream_mruby_mrb_code_from_file(cf->pool, &value[1]);

  if (code == NGX_CONF_UNSET_PTR) {
    return NGX_CONF_ERROR;
  }

  rc = ngx_stream_mruby_shared_state_compile(cf, mrb, code);

  mscf->code = code;

  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_stream_mruby_server_context_code(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  mrb_state *mrb = ngx_stream_mrb_state_conf(cf);
  ngx_stream_mruby_srv_conf_t *mscf = conf;
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_int_t rc;
  mrb_int ai;
  void *tmp_ud;

  mscf->ctx->cf = cf;
  mscf->ctx->cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

  value = cf->args->elts;
  code = ngx_stream_mruby_mrb_code_from_string(cf->pool, &value[1]);

  if (code == NGX_CONF_UNSET_PTR) {
    return NGX_CONF_ERROR;
  }

  rc = ngx_stream_mruby_shared_state_compile(cf, mrb, code);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mrb, code);

  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  ai = mrb_gc_arena_save(mrb);

  tmp_ud = mrb->ud;
  mrb->ud = mscf;
  mrb_toplevel_run(mrb, code->proc);
  mrb->ud = tmp_ud;

  if (mrb->exc) {
    ngx_stream_mruby_raise_conf_error(mrb, mrb_obj_value(mrb->exc), cf);
    ngx_stream_mrb_state_clean(mrb);
    mrb_gc_arena_restore(mrb, ai);
    return NGX_CONF_ERROR;
  }

  ngx_stream_mrb_state_clean(mrb);
  mrb_gc_arena_restore(mrb, ai);

  return NGX_CONF_OK;
}

/* set directive values from inline code*/
static char *ngx_stream_mruby_build_code(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  mrb_state *mrb = ngx_stream_mrb_state_conf(cf);
  ngx_stream_mruby_srv_conf_t *mscf = conf;
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_int_t rc;

  mscf->ctx->mrb = mrb;

  value = cf->args->elts;
  code = ngx_stream_mruby_mrb_code_from_string(cf->pool, &value[1]);

  if (code == NGX_CONF_UNSET_PTR) {
    return NGX_CONF_ERROR;
  }

  rc = ngx_stream_mruby_shared_state_compile(cf, mrb, code);

  mscf->code = code;

  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

/*
static void ngx_stream_mrb_raise_conf_error(mrb_state *mrb, mrb_value obj, ngx_conf_t *cf)
{
  obj = mrb_funcall(mrb, obj, "inspect", 0);
  if (mrb_type(obj) == MRB_TT_STRING) {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "mrb_run failed. error: %*s", RSTRING_LEN(obj), RSTRING_PTR(obj));
  }
}

static ngx_int_t ngx_stream_mrb_run_conf(ngx_conf_t *cf, mrb_state *mrb, ngx_mrb_code_t *code)
{
  int ai = mrb_gc_arena_save(mrb);

  ngx_log_error(NGX_LOG_INFO, cf->log, 0, "%s INFO %s:%d: mrb_run", MODULE_NAME, __func__, __LINE__);
  mrb_run(mrb, code->proc, mrb_top_self(mrb));
  if (mrb->exc) {
    ngx_stream_mrb_raise_conf_error(mrb, mrb_obj_value(mrb->exc), cf);
    mrb_gc_arena_restore(mrb, ai);
    return NGX_ERROR;
  }

  mrb_gc_arena_restore(mrb, ai);
  return NGX_OK;
}
*/

static ngx_int_t ngx_stream_mruby_handler(ngx_stream_session_t *s)
{
  ngx_stream_mruby_srv_conf_t *mscf;
  mrb_state *mrb;
  mrb_int ai;
  ngx_stream_mruby_internal_ctx_t *ictx;

  mscf = ngx_stream_get_module_srv_conf(s, ngx_stream_mruby_module);
  if (mscf->code == NGX_CONF_UNSET_PTR) {
    return NGX_DECLINED;
  }

  mrb = ngx_stream_mrb_state(s);
  ai = mrb_gc_arena_save(mrb);
  ictx = mrb->ud;

  ictx->s = s;
  ictx->stream_status = NGX_DECLINED;

  mrb_value *mrb_result = (mrb_value *)ngx_palloc(s->connection->pool, sizeof(mrb_value));
  *mrb_result = mrb_nil_value();

  if (mrb_test(ngx_stream_mrb_start_fiber(s, mrb, mscf->code->proc, mrb_result))) {
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "%s INFO %s:%d: already can resume this fiber", MODULE_NAME,
                  __func__, __LINE__);

    mrb_gc_arena_restore(mrb, ai);
    return NGX_DONE;
  } else {
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "%s INFO %s:%d: already finish this fiber, can not resume",
                  MODULE_NAME, __func__, __LINE__);
  }

  if (mrb->exc) {
    ngx_stream_mruby_raise_error(mrb, mrb_obj_value(mrb->exc), s);
    ngx_stream_mrb_state_clean(mrb);
    mrb_gc_arena_restore(mrb, ai);
    return NGX_ABORT;
  }

  ngx_stream_mrb_state_clean(mrb);
  mrb_gc_arena_restore(mrb, ai);

  /* default NGX_DECLINED */
  return ictx->stream_status;
}

/* set mruby_handler to access phase */
static ngx_int_t ngx_stream_mruby_init(ngx_conf_t *cf)
{
  ngx_stream_core_main_conf_t *cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

#if (nginx_version >= 1011005)
  ngx_stream_handler_pt *h;

  h = ngx_array_push(&cmcf->phases[NGX_STREAM_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = ngx_stream_mruby_handler;
#else
  cmcf->access_handler = ngx_stream_mruby_handler;
#endif

  return NGX_OK;
}
