/*
// ngx_http_mruby.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_H
#define NGX_HTTP_MRUBY_H

#include <ngx_http.h>
#include <mruby.h>

typedef struct ngx_mrb_state_t {
    mrb_state *mrb;
    int n;
    int ai;
} ngx_mrb_state_t;

ngx_int_t ngx_mrb_run(ngx_http_request_t *r, ngx_mrb_state_t *mrb);
ngx_int_t ngx_mrb_init_file(char *code_file_path, ngx_mrb_state_t *state);
ngx_int_t ngx_mrb_init_string(char *code, ngx_mrb_state_t *state);

#endif // NGX_HTTP_MRUBY_H
