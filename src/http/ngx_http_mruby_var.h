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

mrb_value ngx_mrb_var_set_vector(mrb_state *mrb, mrb_value self, char *k, int len, mrb_value o, ngx_http_request_t *r);

void ngx_mrb_var_class_init(mrb_state *mrb, struct RClass *class);

#endif // NGX_HTTP_MRUBY_VAR_H
