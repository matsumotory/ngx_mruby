/*
// ngx_stream_mruby_module.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_STREAM_MRUBY_MODULE_H
#define NGX_STREAM_MRUBY_MODULE_H

#include <nginx.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#define MODULE_NAME "ngx_mruby-stream-module"

extern ngx_module_t ngx_stream_mruby_module;

typedef struct {
  ngx_stream_session_t *s;
  ngx_int_t stream_status;
} ngx_stream_mruby_internal_ctx_t;

#endif // NGX_STREAM_MRUBY_MODULE_H
