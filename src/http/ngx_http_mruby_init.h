/*
// ngx_http_mruby_init.h - ngx_mruby mruby init header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_INIT_H
#define NGX_HTTP_MRUBY_INIT_H

#include "ngx_http_mruby_core.h"
#include <mruby.h>
#include <ngx_http.h>

ngx_int_t ngx_mrb_class_init(mrb_state *mrb);

#endif // NGX_HTTP_MRUBY_INIT_H
