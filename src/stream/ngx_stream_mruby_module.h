/*
// ngx_stream_mruby_module.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_STREAM_MRUBY_MODULE_H
#define NGX_STREAM_MRUBY_MODULE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "mruby.h"
#include "mruby/compile.h"

#include "../common/ngx_mruby_code.h"
#include "../common/ngx_mruby_exec.h"

#define MODULE_NAME "ngx_mruby-stream-module"

/*
 * What mrb->ud of the stream module's mrb_state points at. exec comes first,
 * so that mrb->ud is the holder of the execution context
 * (src/common/ngx_mruby_exec.h), which says whether a session runs (its kind
 * is NGX_MRB_EXEC_STREAM and on is the session) and which server
 * configuration the server context code runs for.
 */
typedef struct {
  ngx_mrb_exec_holder_t exec;
  ngx_int_t stream_status;
} ngx_stream_mruby_internal_ctx_t;

typedef struct {
  mrb_state *mrb;
  ngx_conf_t *cf;
  ngx_stream_core_srv_conf_t *cscf;
} ngx_stream_mruby_conf_ctx_t;

typedef struct {

  ngx_stream_mruby_conf_ctx_t *ctx;
  ngx_mrb_code_t *init_code;
  ngx_mrb_code_t *init_worker_code;
  ngx_mrb_code_t *exit_worker_code;

} ngx_stream_mruby_main_conf_t;

typedef struct {

  ngx_stream_mruby_conf_ctx_t *ctx;
  ngx_mrb_code_t *code;

} ngx_stream_mruby_srv_conf_t;

/*
 * The directives with Ruby code that the stream module keeps for later, in
 * the form of NGX_HTTP_MRUBY_CODE_TABLE (src/http/ngx_http_mruby_module.h).
 * ngx_stream_mruby_module.c makes the command entries of each row and the
 * registration of the session handler. Both forms of a row set one field,
 * field (an offsetof) of the configuration conf (an
 * NGX_STREAM_*_CONF_OFFSET), so that a hook or a server takes one of them.
 * Unlike the http module, both forms take one argument.
 *
 * - HOOK(file, inline_, contexts, conf, field): code that runs outside any
 *   session, once (mruby_stream_init) or in each worker (the worker hooks).
 * - SESSION(phase, file, inline_, contexts, conf, field): the code of a
 *   session, which ngx_stream_mruby_handler runs in phase.
 *
 * mruby_stream_server_context_code runs while nginx reads the configuration
 * and is not kept, so it is written out in ngx_stream_mruby_module.c.
 */
#define NGX_STREAM_MRUBY_CODE_TABLE(HOOK, SESSION)                                                                     \
  HOOK("mruby_stream_init", "mruby_stream_init_code", NGX_STREAM_MAIN_CONF, NGX_STREAM_MAIN_CONF_OFFSET,               \
       offsetof(ngx_stream_mruby_main_conf_t, init_code))                                                              \
  HOOK("mruby_stream_init_worker", "mruby_stream_init_worker_code", NGX_STREAM_MAIN_CONF, NGX_STREAM_MAIN_CONF_OFFSET, \
       offsetof(ngx_stream_mruby_main_conf_t, init_worker_code))                                                       \
  HOOK("mruby_stream_exit_worker", "mruby_stream_exit_worker_code", NGX_STREAM_MAIN_CONF, NGX_STREAM_MAIN_CONF_OFFSET, \
       offsetof(ngx_stream_mruby_main_conf_t, exit_worker_code))                                                       \
  SESSION(NGX_STREAM_ACCESS_PHASE, "mruby_stream", "mruby_stream_code", NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF,    \
          NGX_STREAM_SRV_CONF_OFFSET, offsetof(ngx_stream_mruby_srv_conf_t, code))

void ngx_stream_mruby_raise_error(mrb_state *mrb, mrb_value obj, ngx_stream_session_t *s);
#endif // NGX_STREAM_MRUBY_MODULE_H
