/*
// ngx_http_mruby_request.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_REQUEST_H
#define NGX_HTTP_MRUBY_REQUEST_H

#include "ngx_http_mruby_var.h"
#include <mruby.h>
#include <mruby/hash.h>
#include <mruby/variable.h>
#include <ngx_http.h>

ngx_int_t ngx_mrb_push_request(ngx_http_request_t *r);
ngx_http_request_t *ngx_mrb_get_request(void);
mrb_value ngx_mrb_get_request_var(mrb_state *mrb, mrb_value self);

#endif // NGX_HTTP_MRUBY_REQUEST_H
