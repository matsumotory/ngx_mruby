/*
// ngx_stream_mruby_core.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_STREAM_MRUBY_CORE_H
#define NGX_STREAM_MRUBY_CORE_H

#include <mruby.h>
#include <mruby/compile.h>
#include <ngx_stream.h>

void ngx_mrb_raise_error(mrb_state *mrb, mrb_value obj, ngx_stream_session_t *s);

#endif // NGX_STREAM_MRUBY_CORE_H
