/*
// ngx_http_mruby_debug.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_DEBUG_H
#define NGX_HTTP_MRUBY_DEBUG_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <mruby.h>

#ifdef NGX_MRUBY_DEBUG_STATS
void ngx_mrb_debug_class_init(mrb_state *mrb, struct RClass *class);
#endif

#endif // NGX_HTTP_MRUBY_DEBUG_H
