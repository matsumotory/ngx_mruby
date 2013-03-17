/*
// ngx_http_mruby_state.h - ngx_mruby mruby state functions
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_STATE_H
#define NGX_HTTP_MRUBY_STATE_H

#include <nginx.h>
#include "ngx_http_mruby_core.h"

ngx_mrb_state_t *ngx_http_mruby_mrb_state_from_file(ngx_pool_t *pool, ngx_str_t *value);
ngx_mrb_state_t *ngx_http_mruby_mrb_state_from_string(ngx_pool_t *pool, ngx_str_t *code);

#endif // NGX_HTTP_MRUBY_STATE_H
