/*
// ngx_http_mruby_core.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_CORE_H
#define NGX_HTTP_MRUBY_CORE_H

#include <ngx_http.h>
#include <mruby.h>

typedef struct ngx_mrb_state_t {
    mrb_state *mrb;
    char *file;
    int n;
    int ai;
} ngx_mrb_state_t;

void ngx_mrb_core_init(mrb_state *mrb, struct RClass *class);
ngx_int_t ngx_mrb_run(ngx_http_request_t *r, ngx_mrb_state_t *mrb);

#endif // NGX_HTTP_MRUBY_CORE_H
