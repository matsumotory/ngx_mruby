/*
// ngx_http_mruby_core.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_CORE_H
#define NGX_HTTP_MRUBY_CORE_H

#include <ngx_http.h>
#include <mruby.h>

typedef enum code_type_t {
    NGX_MRB_CODE_TYPE_FILE,
    NGX_MRB_CODE_TYPE_STRING
} code_type_t;

typedef struct ngx_mrb_state_t {
    mrb_state *mrb;
    int ai;
} ngx_mrb_state_t;

typedef struct ngx_mrb_code_t {
    union code {
        char *file;
        char *string;
    } code;
    code_type_t code_type;
    int n;
} ngx_mrb_code_t;

typedef struct ngx_mrb_rputs_chain_list_t {
    ngx_chain_t **last;
    ngx_chain_t *out;
} ngx_mrb_rputs_chain_list_t;

typedef struct ngx_http_mruby_ctx_t {
    ngx_mrb_rputs_chain_list_t *rputs_chain;
    u_char *body;
    u_char *last;
    size_t body_length;
} ngx_http_mruby_ctx_t;

void ngx_mrb_core_init(mrb_state *mrb, struct RClass *class);
ngx_int_t ngx_mrb_run(ngx_http_request_t *r, ngx_mrb_state_t *state, ngx_mrb_code_t *code, ngx_flag_t cached, ngx_str_t *result);
ngx_int_t ngx_mrb_run_conf(ngx_conf_t *cf, ngx_mrb_state_t *state, ngx_mrb_code_t *code);
ngx_int_t ngx_mrb_run_body_filter(ngx_http_request_t *r, ngx_mrb_state_t *state, ngx_mrb_code_t *code, ngx_flag_t cached, ngx_http_mruby_ctx_t *ctx);

#endif // NGX_HTTP_MRUBY_CORE_H
