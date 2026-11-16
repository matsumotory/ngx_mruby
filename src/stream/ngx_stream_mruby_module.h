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

void ngx_stream_mruby_raise_error(mrb_state *mrb, mrb_value obj, ngx_stream_session_t *s);
#endif // NGX_STREAM_MRUBY_MODULE_H
