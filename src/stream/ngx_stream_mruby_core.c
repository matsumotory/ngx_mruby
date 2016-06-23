/*
// ngx_stream_mruby_core.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_stream_mruby_core.h"
#include "ngx_stream_mruby_module.h"

#include "mruby.h"
#include "mruby/array.h"
#include "mruby/compile.h"
#include "mruby/data.h"
#include "mruby/proc.h"
#include "mruby/string.h"
#include "mruby/variable.h"

#include <nginx.h>
#include <ngx_buf.h>
#include <ngx_conf_file.h>
#include <ngx_log.h>
#include <ngx_stream.h>

static mrb_value ngx_stream_mrb_errlogger(mrb_state *mrb, mrb_value self)
{
  mrb_value *argv;
  mrb_value msg;
  mrb_int argc;
  mrb_int log_level;
  ngx_stream_mruby_internal_ctx_t *ictx = mrb->ud;
  ngx_stream_session_t *s = ictx->s;

  if (s == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't use logger at this phase. only use at session stream phase");
  }

  mrb_get_args(mrb, "*", &argv, &argc);
  if (argc != 2) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%s ERROR %s: argument is not 2", MODULE_NAME, __func__);
    return self;
  }
  if (mrb_type(argv[0]) != MRB_TT_FIXNUM) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%s ERROR %s: argv[0] is not integer", MODULE_NAME, __func__);
    return self;
  }
  log_level = mrb_fixnum(argv[0]);
  if (log_level < 0) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%s ERROR %s: log level is not positive number", MODULE_NAME,
                  __func__);
    return self;
  }
  if (mrb_type(argv[1]) != MRB_TT_STRING) {
    msg = mrb_funcall(mrb, argv[1], "to_s", 0, NULL);
  } else {
    msg = mrb_str_dup(mrb, argv[1]);
  }
  ngx_log_error((ngx_uint_t)log_level, s->connection->log, 0, "%s", mrb_str_to_cstr(mrb, msg));

  return self;
}

static mrb_value ngx_stream_mrb_get_ngx_mruby_name(mrb_state *mrb, mrb_value self)
{
  return mrb_str_new_lit(mrb, MODULE_NAME);
}

void ngx_stream_mrb_core_class_init(mrb_state *mrb, struct RClass *class)
{
  mrb_define_const(mrb, class, "OK", mrb_fixnum_value(NGX_OK));
  mrb_define_const(mrb, class, "ERROR", mrb_fixnum_value(NGX_ERROR));
  mrb_define_const(mrb, class, "AGAIN", mrb_fixnum_value(NGX_AGAIN));
  mrb_define_const(mrb, class, "BUSY", mrb_fixnum_value(NGX_BUSY));
  mrb_define_const(mrb, class, "DONE", mrb_fixnum_value(NGX_DONE));
  mrb_define_const(mrb, class, "DECLINED", mrb_fixnum_value(NGX_DECLINED));
  mrb_define_const(mrb, class, "ABORT", mrb_fixnum_value(NGX_ABORT));
  // error log priority
  mrb_define_const(mrb, class, "LOG_STDERR", mrb_fixnum_value(NGX_LOG_STDERR));
  mrb_define_const(mrb, class, "LOG_EMERG", mrb_fixnum_value(NGX_LOG_EMERG));
  mrb_define_const(mrb, class, "LOG_ALERT", mrb_fixnum_value(NGX_LOG_ALERT));
  mrb_define_const(mrb, class, "LOG_CRIT", mrb_fixnum_value(NGX_LOG_CRIT));
  mrb_define_const(mrb, class, "LOG_ERR", mrb_fixnum_value(NGX_LOG_ERR));
  mrb_define_const(mrb, class, "LOG_WARN", mrb_fixnum_value(NGX_LOG_WARN));
  mrb_define_const(mrb, class, "LOG_NOTICE", mrb_fixnum_value(NGX_LOG_NOTICE));
  mrb_define_const(mrb, class, "LOG_INFO", mrb_fixnum_value(NGX_LOG_INFO));
  mrb_define_const(mrb, class, "LOG_DEBUG", mrb_fixnum_value(NGX_LOG_DEBUG));

  mrb_define_class_method(mrb, class, "errlogger", ngx_stream_mrb_errlogger, MRB_ARGS_ANY());
  mrb_define_class_method(mrb, class, "log", ngx_stream_mrb_errlogger, MRB_ARGS_ANY());
  mrb_define_class_method(mrb, class, "module_name", ngx_stream_mrb_get_ngx_mruby_name, MRB_ARGS_NONE());
}
