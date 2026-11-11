/*
// ngx_mruby_log.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

/*
// The error log lines of an exception of Ruby code, and the body of
// Nginx.log, which the http (src/http/) and the stream (src/stream/) modules
// share. See ngx_mruby_log.h.
*/

#include "ngx_mruby_log.h"

#include <mruby/array.h>
#include <mruby/presym.h>
#include <mruby/string.h>

#if (NGX_DEBUG)
static void ngx_mrb_log_backtrace(mrb_state *mrb, mrb_value exc, ngx_log_t *log)
{
  mrb_value bt, frame;
  mrb_int i;

  if (mrb_type(exc) != MRB_TT_EXCEPTION) {
    return;
  }
  bt = mrb_funcall_id(mrb, exc, MRB_SYM(backtrace), 0);
  if (!mrb_array_p(bt)) {
    ngx_log_error(NGX_LOG_DEBUG, log, 0, "backtrace must be Array. mrb_type=%d", mrb_type(bt));
    return;
  }
  // #backtrace may be redefined by a script, so its result can hold any
  // object. Reading an element that is not a String as one would be
  // undefined behavior: such an element is skipped.
  for (i = 0; i < RARRAY_LEN(bt); i++) {
    frame = RARRAY_PTR(bt)[i];
    if (!mrb_string_p(frame)) {
      continue;
    }
    ngx_log_error(NGX_LOG_ERR, log, 0, "%*s", RSTRING_LEN(frame), RSTRING_PTR(frame));
  }
}
#endif

void ngx_mrb_log_exception(mrb_state *mrb, mrb_value exc, ngx_log_t *log, ngx_conf_t *cf, ngx_uint_t level,
                           const char *prefix)
{
  mrb_value s;

  if (cf != NULL) {
    log = cf->log;
  }
  s = mrb_funcall_id(mrb, exc, MRB_SYM(inspect), 0);
  if (mrb_string_p(s)) {
    if (cf != NULL) {
      ngx_conf_log_error(level, cf, 0, "%s%*s", prefix, RSTRING_LEN(s), RSTRING_PTR(s));
    } else {
      ngx_log_error(level, log, 0, "%s%*s", prefix, RSTRING_LEN(s), RSTRING_PTR(s));
    }
  }
#if (NGX_DEBUG)
  ngx_mrb_log_backtrace(mrb, exc, log);
#endif
}

mrb_value ngx_mrb_log_method(mrb_state *mrb, mrb_value self, ngx_log_t *log, const char *module_name, const char *func)
{
  mrb_value msg;
  mrb_int log_level;

  mrb_get_args(mrb, "io", &log_level, &msg);
  if (log_level < 0) {
    ngx_log_error(NGX_LOG_ERR, log, 0, "%s ERROR %s: log level is not positive number", module_name, func);
    return self;
  }
  msg = mrb_obj_as_string(mrb, msg);
  ngx_log_error((ngx_uint_t)log_level, log, 0, "%*s", RSTRING_LEN(msg), RSTRING_PTR(msg));

  return self;
}
