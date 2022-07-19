/*
// ngx_stream_mruby_connection.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_STREAM_MRUBY_CONNECTION_H
#define NGX_STREAM_MRUBY_CONNECTION_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <mruby.h>

void ngx_stream_mrb_conn_class_init(mrb_state *mrb, struct RClass *class);

#endif // NGX_STREAM_MRUBY_CONNECTION_H
