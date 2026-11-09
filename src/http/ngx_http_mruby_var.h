/*
// ngx_http_mruby_var.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_var.c
*/

#ifndef NGX_HTTP_MRUBY_VAR_H
#define NGX_HTTP_MRUBY_VAR_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <mruby.h>

/*
 * The value of a variable, or the argument of Nginx.rputs, Nginx.echo,
 * Nginx.redirect and Nginx::Filter#body=, as a String in *out: o itself when
 * it is a String, else what its to_s returns. to_s runs under
 * mrb_protect_error(), so this also works where no Ruby code runs (mrb->jmp
 * is NULL), as at the end of an mruby_set handler. A to_s that is missing, that raises or that does not
 * return a String gives FALSE, with the exception in *out (a TypeError for
 * the last). mrb->exc is NULL afterwards.
 */
mrb_bool ngx_mrb_var_to_string(mrb_state *mrb, mrb_value o, mrb_value *out);

/*
 * Sets the variable to o, which must be a String: convert other values with
 * ngx_mrb_var_to_string() first. Another value leaves the variable as it was
 * and returns nil.
 */
mrb_value ngx_mrb_var_set_vector(mrb_state *mrb, mrb_value self, char *k, int len, mrb_value o, ngx_http_request_t *r);

void ngx_mrb_var_class_init(mrb_state *mrb, struct RClass *class);

#endif // NGX_HTTP_MRUBY_VAR_H
