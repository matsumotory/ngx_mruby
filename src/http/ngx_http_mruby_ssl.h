/*
// ngx_http_mruby_ssl.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_SSL_H
#define NGX_HTTP_MRUBY_SSL_H

#include <ngx_config.h>
// #include <ngx_core.h>

#if (NGX_HTTP_SSL)

#include <mruby.h>

void ngx_mrb_ssl_class_init(mrb_state *mrb, struct RClass *class);

#endif // NGX_HTTP_SSL

#endif // NGX_HTTP_MRUBY_SSL_H
