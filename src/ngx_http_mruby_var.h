/*
// ngx_http_mruby_var.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_var.c
*/

#ifndef NGX_HTTP_MRUBY_VAR_H
#define NGX_HTTP_MRUBY_VAR_H

#include <ngx_http.h>
#include <mruby.h>
#include <mruby/hash.h>
#include <mruby/variable.h>
#include "ngx_http_mruby_module.h"
#include "ngx_http_mruby_request.h"

void ngx_mrb_var_class_init(mrb_state *mrb, struct RClass *calss);

#endif // NGX_HTTP_MRUBY_VAR_H
