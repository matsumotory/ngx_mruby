/*
// ngx_http_mruby_module.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_MODULE_H
#define NGX_HTTP_MRUBY_MODULE_H

#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#define MODULE_NAME        "ngx_mruby"
#define MODULE_VERSION     "0.0.1"

#define DONE mrb_gc_arena_restore(mrb, 0);

extern ngx_module_t  ngx_http_mruby_module;

#endif // NGX_HTTP_MRUBY_MODULE_H
