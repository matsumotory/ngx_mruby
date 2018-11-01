/*
// ngx_http_mruby_filter.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_FILTER_H
#define NGX_HTTP_MRUBY_FILTER_H

#include <mruby.h>

void ngx_mrb_filter_class_init(mrb_state *mrb, struct RClass *class);

#endif // NGX_HTTP_MRUBY_FILTER_H
