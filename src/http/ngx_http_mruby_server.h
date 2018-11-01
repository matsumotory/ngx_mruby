/*
// ngx_http_mruby_server.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_SERVER_H
#define NGX_HTTP_MRUBY_SERVER_H

#include <mruby.h>

void ngx_mrb_server_class_init(mrb_state *mrb, struct RClass *class);

#endif // NGX_HTTP_MRUBY_SERVER_H
