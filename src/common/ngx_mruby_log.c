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

/* The longest line that names the class of an exception in place of its
   inspect, without the text before it. */
#define NGX_MRB_LOG_TEXT_MAX 512

/* A call that the logging makes on an object of the script. */
typedef struct {
  mrb_value obj;
  mrb_sym mid;         /* the method to call, when class_name is FALSE */
  mrb_bool class_name; /* take the name of the class of obj instead */
} ngx_mrb_log_call_t;

static mrb_value ngx_mrb_log_call_body(mrb_state *mrb, void *data)
{
  ngx_mrb_log_call_t *call = data;

  if (call->class_name) {
    return mrb_str_new_cstr(mrb, mrb_obj_classname(mrb, call->obj));
  }
  return mrb_funcall_id(mrb, call->obj, call->mid, 0);
}

/*
// Calls obj.mid (or, with class_name, takes the name of the class of obj),
// stores what it returned, or the exception that it raised, in *result, and
// returns whether it returned. A script can redefine #inspect and #backtrace
// so that they raise. mrb_funcall catches that exception itself only when no
// other mruby call is on the C stack (mrb->jmp is NULL). Inside another one,
// for example in the handler of a location that Nginx.redirect runs from Ruby
// code, it would go to that call's mrb->jmp past the nginx functions between
// the two; ngx_mrb_fiber_resume protects the resumed fiber in the same way.
// mrb_protect_error stops the exception here on both paths. mrb->exc, which
// the caller may still hold (the exception that is being logged), is
// cleared during the call and put back afterwards, so that the exception of
// the call is not left in it.
*/
static mrb_bool ngx_mrb_log_call(mrb_state *mrb, mrb_value obj, mrb_sym mid, mrb_bool class_name, mrb_value *result)
{
  struct RObject *exc = mrb->exc;
  ngx_mrb_log_call_t call;
  mrb_bool raised;

  call.obj = obj;
  call.mid = mid;
  call.class_name = class_name;
  mrb->exc = NULL;
  *result = mrb_protect_error(mrb, ngx_mrb_log_call_body, &call, &raised);
  mrb->exc = exc;
  return !raised;
}

#if (NGX_DEBUG)
static void ngx_mrb_log_backtrace(mrb_state *mrb, mrb_value exc, ngx_log_t *log)
{
  mrb_value bt, frame;
  mrb_int i;

  if (mrb_type(exc) != MRB_TT_EXCEPTION) {
    return;
  }
  // a #backtrace that raises is logged as one that does not return an Array
  if (!ngx_mrb_log_call(mrb, exc, MRB_SYM(backtrace), FALSE, &bt) || !mrb_array_p(bt)) {
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
  mrb_value s, name;
  mrb_bool returned;
  u_char text[NGX_MRB_LOG_TEXT_MAX], *p;
  size_t len;
  ngx_str_t exc_class, raised_class;

  if (cf != NULL) {
    log = cf->log;
  }
  // The exception may be held only by mrb->exc, which ngx_mrb_log_call
  // clears during its calls: the GC arena keeps it until the caller restores
  // the arena.
  mrb_gc_protect(mrb, exc);
  returned =ngx_mrb_log_call(mrb, exc, MRB_SYM(inspect), FALSE, &s);
  if (returned && mrb_string_p(s)) {
    p = (u_char *)RSTRING_PTR(s);
    len = RSTRING_LEN(s);
  } else {
    // #inspect raised or did not return a String: the line names the class
    // of the exception, and, when #inspect raised, the class of the
    // exception of #inspect
    ngx_str_set(&exc_class, "?");
    if (ngx_mrb_log_call(mrb, exc, 0, TRUE, &name)) {
      exc_class.data = (u_char *)RSTRING_PTR(name);
      exc_class.len = RSTRING_LEN(name);
    }
    if (returned) {
      p = ngx_snprintf(text, sizeof(text), "#<%V> (inspect did not return a String)", &exc_class);
    } else {
      ngx_str_set(&raised_class, "?");
      if (ngx_mrb_log_call(mrb, s, 0, TRUE, &name)) {
        raised_class.data = (u_char *)RSTRING_PTR(name);
        raised_class.len = RSTRING_LEN(name);
      }
      p = ngx_snprintf(text, sizeof(text), "#<%V> (inspect raised %V)", &exc_class, &raised_class);
    }
    len = p - text;
    p = text;
  }
  if (cf != NULL) {
    ngx_conf_log_error(level, cf, 0, "%s%*s", prefix, len, p);
  } else {
    ngx_log_error(level, log, 0, "%s%*s", prefix, len, p);
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
