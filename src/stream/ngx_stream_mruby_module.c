/*
// ngx_stream_mruby_module.c - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_stream_mruby_module.h"
#include "ngx_stream_mruby_core.h"
#include "ngx_stream_mruby_async.h"
#include "../http/ngx_http_mruby_gc_roots.h"

#include "ngx_stream_mruby_init.h"

#include "../common/ngx_mruby_log.h"

#include <mruby/presym.h>
#include <mruby/proc.h>
#include "mruby/string.h"

/* stream session mruby handler */
static ngx_int_t ngx_stream_mruby_handler(ngx_stream_session_t *s);

/* stream session mruby directive functions */
// the directives of NGX_STREAM_MRUBY_CODE_TABLE
static char *ngx_stream_mruby_code_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_stream_mruby_server_context_code(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* mruby core functions for compile */
static void ngx_stream_mrb_state_clean(mrb_state *mrb);
static ngx_int_t ngx_stream_mrb_run_cycle(ngx_cycle_t *cycle, mrb_state *mrb, ngx_mrb_code_t *code,
                                         ngx_mrb_exec_kind_t kind);
// static ngx_int_t ngx_stream_mrb_run_conf(ngx_conf_t *cf, mrb_state *mrb, ngx_mrb_code_t *code);

/* ngx_mruby stream module init and exit handlers */
static ngx_int_t ngx_stream_mruby_init_module(ngx_cycle_t *cycle);
static ngx_int_t ngx_stream_mruby_init_worker(ngx_cycle_t *cycle);
static void ngx_stream_mruby_exit_worker(ngx_cycle_t *cycle);

/* setup main and srv configuration */
static void *ngx_stream_mruby_create_main_conf(ngx_conf_t *cf);
static char *ngx_stream_mruby_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_stream_mruby_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_mruby_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

/* ngx_mruby stream init function after creating main and srv configuration */
static ngx_int_t ngx_stream_mruby_init(ngx_conf_t *cf);

#define NGX_STREAM_MRUBY_TABLE_SKIP(...)

// the two command entries of each row of NGX_STREAM_MRUBY_CODE_TABLE
#define NGX_STREAM_MRUBY_HOOK_COMMANDS(file, inline_, contexts, conf, field)                                           \
  {ngx_string(file), (contexts) | NGX_CONF_TAKE1, ngx_stream_mruby_code_directive, conf, field,                        \
   NGX_MRB_CODE_FORM_POST(NGX_MRB_CODE_TYPE_FILE)},                                                                    \
      {ngx_string(inline_), (contexts) | NGX_CONF_TAKE1, ngx_stream_mruby_code_directive, conf, field,                 \
       NGX_MRB_CODE_FORM_POST(NGX_MRB_CODE_TYPE_STRING)},

#define NGX_STREAM_MRUBY_SESSION_COMMANDS(phase, ...) NGX_STREAM_MRUBY_HOOK_COMMANDS(__VA_ARGS__)

static ngx_command_t ngx_stream_mruby_commands[] = {

    NGX_STREAM_MRUBY_CODE_TABLE(NGX_STREAM_MRUBY_HOOK_COMMANDS, NGX_STREAM_MRUBY_SESSION_COMMANDS)

    {ngx_string("mruby_stream_server_context_code"), NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
     ngx_stream_mruby_server_context_code, NGX_STREAM_SRV_CONF_OFFSET, 0, NULL},

    ngx_null_command};

static ngx_stream_module_t ngx_stream_mruby_module_ctx = {
    NULL,                  /* preconfiguration */
    ngx_stream_mruby_init, /* postconfiguration */

    ngx_stream_mruby_create_main_conf, /* create main configuration */
    ngx_stream_mruby_init_main_conf,   /* init main configuration */

    ngx_stream_mruby_create_srv_conf, /* create server configuration */
    ngx_stream_mruby_merge_srv_conf   /* merge server configuration */
};

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
  if (mmcf->ctx->mrb == NULL) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s: mrb_open() failed", MODULE_NAME);
    return NULL;
  }
  /* mruby 4.x returns the state with mrb->exc set, instead of NULL, when the
     initialization of the core or of an mrbgem raised. What comes after the
     raise is not initialized, so the state is not used. */
  if (mmcf->ctx->mrb->exc != NULL) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s: mrb_open() failed: %s raised while initializing mruby", MODULE_NAME,
                       mrb_obj_classname(mmcf->ctx->mrb, mrb_obj_value(mmcf->ctx->mrb->exc)));
    mrb_close(mmcf->ctx->mrb);
    mmcf->ctx->mrb = NULL;
    return NULL;
  }
  ngx_stream_mrb_class_init(mmcf->ctx->mrb);
  if (ngx_mrb_gc_roots_init(mmcf->ctx->mrb) != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s: failed to make the GC root holder of the mrb_state", MODULE_NAME);
    mrb_close(mmcf->ctx->mrb);
    mmcf->ctx->mrb = NULL;
    return NULL;
  }

  cln->handler = ngx_stream_mruby_cleanup;
  cln->data = mmcf;

  ictx = ngx_pcalloc(cf->pool, sizeof(ngx_stream_mruby_internal_ctx_t));
  if (ictx == NULL) {
    return NULL;
  }
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
/* The line of an exception of the code of a session (ngx_mrb_log_exception). */
void ngx_stream_mruby_raise_error(mrb_state *mrb, mrb_value obj, ngx_stream_session_t *s)
{
  ngx_mrb_log_exception(mrb, obj, s->connection->log, NULL, NGX_LOG_ERR,
                        "mrb_run failed: return NGX_ABORT to client: error: ");
}

static ngx_int_t ngx_stream_mruby_init_module(ngx_cycle_t *cycle)
{
  ngx_stream_mruby_main_conf_t *mmcf = ngx_stream_cycle_get_module_main_conf(cycle, ngx_stream_mruby_module);

  if (mmcf == NULL)
    return NGX_OK;

  if (mmcf->init_code != NGX_CONF_UNSET_PTR)
    return ngx_stream_mrb_run_cycle(cycle, mmcf->ctx->mrb, mmcf->init_code, NGX_MRB_EXEC_INIT);

  return NGX_OK;
}

static ngx_int_t ngx_stream_mruby_init_worker(ngx_cycle_t *cycle)
{
  ngx_stream_mruby_main_conf_t *mmcf = ngx_stream_cycle_get_module_main_conf(cycle, ngx_stream_mruby_module);

  if (mmcf == NULL)
    return NGX_OK;

  if (mmcf->init_worker_code != NGX_CONF_UNSET_PTR)
    return ngx_stream_mrb_run_cycle(cycle, mmcf->ctx->mrb, mmcf->init_worker_code, NGX_MRB_EXEC_WORKER);

  return NGX_OK;
}

static void ngx_stream_mruby_exit_worker(ngx_cycle_t *cycle)
{
  ngx_stream_mruby_main_conf_t *mmcf = ngx_stream_cycle_get_module_main_conf(cycle, ngx_stream_mruby_module);

  if (mmcf == NULL)
    return;

  if (mmcf->exit_worker_code != NGX_CONF_UNSET_PTR)
    ngx_stream_mrb_run_cycle(cycle, mmcf->ctx->mrb, mmcf->exit_worker_code, NGX_MRB_EXEC_WORKER);
}

/* ngx_mruby stream core functions */
static void ngx_stream_mrb_state_clean(mrb_state *mrb)
{
  mrb->exc = 0;
}

// kind is NGX_MRB_EXEC_INIT for mruby_stream_init and NGX_MRB_EXEC_WORKER for
// the worker hooks
static ngx_int_t ngx_stream_mrb_run_cycle(ngx_cycle_t *cycle, mrb_state *mrb, ngx_mrb_code_t *code,
                                         ngx_mrb_exec_kind_t kind)
{
  mrb_int ai = mrb_gc_arena_save(mrb);
  ngx_mrb_exec_t exec = {kind, NULL, NULL, NULL, NULL, NULL};

  /* init, init_worker and exit_worker code runs outside of any session */
  ngx_mrb_exec_push(mrb, &exec);
  mrb_toplevel_run(mrb, code->proc);
  ngx_mrb_exec_pop(mrb, &exec);
  if (mrb->exc) {
    ngx_mrb_log_exception(mrb, mrb_obj_value(mrb->exc), cycle->log, NULL, NGX_LOG_ERR, "mrb_run failed. error: ");
    mrb_gc_arena_restore(mrb, ai);
    return NGX_ERROR;
  }

  mrb_gc_arena_restore(mrb, ai);
  return NGX_OK;
}

/*
 * The directives of NGX_STREAM_MRUBY_CODE_TABLE: the file and the inline form
 * of a row set one field (the offset of the command) of the main or the
 * server configuration, and the post of the command gives the form. A second
 * directive for the field of a context is refused (ngx_mrb_code_set).
 */
static char *ngx_stream_mruby_code_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  mrb_state *mrb = ngx_stream_mrb_state_conf(cf);
  ngx_mrb_code_t **field = (ngx_mrb_code_t **)((u_char *)conf + cmd->offset);

  if (cmd->conf == NGX_STREAM_SRV_CONF_OFFSET) {
    // the cleanup of the server configuration frees the compiler context of
    // the code with this state
    ((ngx_stream_mruby_srv_conf_t *)conf)->ctx->mrb = mrb;
  }

  return ngx_mrb_code_set(cf, mrb, field, NGX_MRB_CODE_FORM_OF(cmd), MODULE_NAME, __func__);
}

static char *ngx_stream_mruby_server_context_code(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  mrb_state *mrb = ngx_stream_mrb_state_conf(cf);
  ngx_stream_mruby_srv_conf_t *mscf = conf;
  ngx_str_t *value;
  ngx_mrb_code_t *code;
  ngx_int_t rc;
  mrb_int ai;
  ngx_mrb_exec_t exec = {NGX_MRB_EXEC_STREAM_SERVER_CONTEXT, cf, mscf, NULL, NULL, NULL};

  mscf->ctx->cf = cf;
  mscf->ctx->cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

  value = cf->args->elts;
  code = ngx_mrb_code_from_string(cf->pool, &value[1]);

  if (code == NGX_CONF_UNSET_PTR) {
    return NGX_CONF_ERROR;
  }

  rc = ngx_mrb_code_compile(cf, mrb, code, MODULE_NAME, __func__);
  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mrb, code);

  if (rc != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_string(%s) load failed", value[1].data);
    return NGX_CONF_ERROR;
  }

  ai = mrb_gc_arena_save(mrb);

  /*
   * The execution context points Nginx::Stream.add_listener at this server
   * configuration only while the code runs. cf is the parser state of this
   * directive, so it is cleared when the code returns.
   */
  ngx_mrb_exec_push(mrb, &exec);
  mrb_toplevel_run(mrb, code->proc);
  ngx_mrb_exec_pop(mrb, &exec);
  mscf->ctx->cf = NULL;
  mscf->ctx->cscf = NULL;

  if (mrb->exc) {
    ngx_mrb_log_exception(mrb, mrb_obj_value(mrb->exc), NULL, cf, NGX_LOG_EMERG,
                          "mrb_run failed: ngx_mruby stream module configuration failed: error: ");
    ngx_stream_mrb_state_clean(mrb);
    mrb_gc_arena_restore(mrb, ai);
    return NGX_CONF_ERROR;
  }

  ngx_stream_mrb_state_clean(mrb);
  mrb_gc_arena_restore(mrb, ai);

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
  ngx_mrb_exec_t exec;
  ngx_mrb_fiber_outcome_t outcome;
  ngx_stream_mruby_ctx_t *ctx;
  ngx_int_t rc;
  mrb_value *mrb_result;

  mscf = ngx_stream_get_module_srv_conf(s, ngx_stream_mruby_module);
  if (mscf->code == NGX_CONF_UNSET_PTR) {
    return NGX_DECLINED;
  }

  mrb = ngx_stream_mrb_state(s);
  ai = mrb_gc_arena_save(mrb);
  ictx = mrb->ud;

  /*
   * Session-scoped Ruby methods find their session in the execution context.
   * It is pushed only while the code runs and the previous one comes back
   * afterwards, so that it never points to a finished session.
   */
  exec.kind = NGX_MRB_EXEC_STREAM;
  exec.on = s;
  exec.srv_conf = NULL;
  exec.record = NULL;
  exec.log = s->connection->log;
  ngx_mrb_exec_push(mrb, &exec);
  ictx->stream_status = NGX_DECLINED;

  // nginx calls the handler again while a record of the session waits: after
  // the wake of its timer, the handler resumes the fiber and returns the
  // result of the code to the checker (section 4.4 of
  // docs/proposals/core-stabilization.md); otherwise the code does not run
  // again (Q4)
  ctx = ngx_stream_get_module_ctx(s, ngx_stream_mruby_module);
  if (ctx != NULL && ctx->sleeping != NULL) {
    rc = ngx_stream_mrb_fiber_call_again(s, ctx, ctx->async_handler_result, &outcome);
    if (rc == NGX_OK) {
      goto resumed;
    }
    mrb_gc_arena_restore(mrb, ai);
    ngx_mrb_exec_pop(mrb, &exec);
    return rc;
  }

  mrb_result = (mrb_value *)ngx_palloc(s->connection->pool, sizeof(mrb_value));
  if (mrb_result == NULL) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%s ERROR %s:%d: failed to allocate the result", MODULE_NAME,
                  __func__, __LINE__);
    mrb_gc_arena_restore(mrb, ai);
    ngx_mrb_exec_pop(mrb, &exec);
    return NGX_ERROR;
  }
  *mrb_result = mrb_nil_value();

  outcome = ngx_stream_mrb_start_fiber(s, mrb, mscf->code->proc, mrb_result);

resumed:
  if (outcome == NGX_MRB_FIBER_WAITS) {
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "%s INFO %s:%d: already can resume this fiber", MODULE_NAME,
                  __func__, __LINE__);

    // While the code waits, a read event of the connection runs the phases,
    // so that this handler finds the waiting record: the code does not start
    // again, the bytes from the client stay unread, and the close that
    // worker_shutdown_timeout asks for ends the wait. On a listen with
    // proxy_protocol, nginx leaves the reader of the PROXY header as the read
    // handler, which does not run the phases; ngx_stream_session_handler
    // takes its place until the code resumes (ngx_stream_mrb_fiber_call_again
    // puts it back).
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_mruby_module);
    if (ctx != NULL && s->connection->read->handler != ngx_stream_session_handler) {
      ctx->read_handler = s->connection->read->handler;
      s->connection->read->handler = ngx_stream_session_handler;
    }

    mrb_gc_arena_restore(mrb, ai);
    ngx_mrb_exec_pop(mrb, &exec);
    return NGX_DONE;
  } else {
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "%s INFO %s:%d: already finish this fiber, can not resume",
                  MODULE_NAME, __func__, __LINE__);
  }

  if (outcome == NGX_MRB_FIBER_RAISED) {
    // ngx_stream_mrb_start_fiber has logged the exception and cleared mrb->exc
    mrb_gc_arena_restore(mrb, ai);
    ngx_mrb_exec_pop(mrb, &exec);
    return NGX_ABORT;
  }

  ngx_stream_mrb_state_clean(mrb);
  mrb_gc_arena_restore(mrb, ai);
  ngx_mrb_exec_pop(mrb, &exec);

  /* default NGX_DECLINED */
  return ictx->stream_status;
}

/* the phases of the SESSION rows of NGX_STREAM_MRUBY_CODE_TABLE */
#define NGX_STREAM_MRUBY_SESSION_PHASE(phase, ...) phase,

static ngx_stream_phases ngx_stream_mruby_session_phases[] = {
    NGX_STREAM_MRUBY_CODE_TABLE(NGX_STREAM_MRUBY_TABLE_SKIP, NGX_STREAM_MRUBY_SESSION_PHASE)};

/* add the session handler to the phase of each SESSION row */
static ngx_int_t ngx_stream_mruby_init(ngx_conf_t *cf)
{
  ngx_stream_core_main_conf_t *cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
  ngx_stream_handler_pt *h;
  ngx_uint_t i;

  for (i = 0; i < sizeof(ngx_stream_mruby_session_phases) / sizeof(ngx_stream_mruby_session_phases[0]); i++) {
    h = ngx_array_push(&cmcf->phases[ngx_stream_mruby_session_phases[i]].handlers);
    if (h == NULL) {
      return NGX_ERROR;
    }

    *h = ngx_stream_mruby_handler;
  }

  return NGX_OK;
}
