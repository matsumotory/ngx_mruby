/*
// ngx_http_mruby_module.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include <nginx.h>
#include <ngx_http.h>

#ifndef NGX_HTTP_MRUBY_FILTER_HANDLER_H
#define NGX_HTTP_MRUBY_FILTER_HANDLER_H

void ngx_http_mruby_header_filter_init(void);
void ngx_http_mruby_body_filter_init(void);

ngx_int_t ngx_http_mruby_header_filter_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_mruby_header_filter_inline_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_mruby_body_filter_handler(ngx_http_request_t *r, ngx_chain_t *in);
ngx_int_t ngx_http_mruby_body_filter_inline_handler(ngx_http_request_t *r, ngx_chain_t *in);

#endif // NGX_HTTP_MRUBY_FILTER_HANDLER_H
