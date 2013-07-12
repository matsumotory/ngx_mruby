/*
// ngx_http_mruby_state.h - ngx_mruby mruby state functions
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_STATE_H
#define NGX_HTTP_MRUBY_STATE_H

#include <nginx.h>
#include <mruby.h>
#include <mruby/value.h>
#include "ngx_http_mruby_core.h"

ngx_int_t ngx_http_mruby_state_reinit_from_file(ngx_mrb_state_t *state, ngx_mrb_code_t *code);
ngx_mrb_code_t *ngx_http_mruby_mrb_code_from_file(ngx_pool_t *pool, ngx_str_t *code_file_path);
ngx_mrb_code_t *ngx_http_mruby_mrb_code_from_string(ngx_pool_t *pool, ngx_str_t *code_s);
ngx_int_t ngx_http_mruby_shared_state_init(ngx_mrb_state_t *state);
ngx_int_t ngx_mrb_init_file(ngx_str_t *script_file_path, ngx_mrb_state_t *state, ngx_mrb_code_t *code);
ngx_int_t ngx_mrb_init_string(ngx_str_t *script, ngx_mrb_state_t *state, ngx_mrb_code_t *code);
ngx_int_t ngx_http_mruby_shared_state_compile(ngx_mrb_state_t *state, ngx_mrb_code_t *code);

#endif // NGX_HTTP_MRUBY_STATE_H
