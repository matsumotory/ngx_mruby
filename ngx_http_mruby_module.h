/*
// ngx_http_mruby_module.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_MODULE_H
#define NGX_HTTP_MRUBY_MODULE_H

#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#include "ngx_http_mruby_core.h"
#include "ngx_http_mruby_init.h"

#define MODULE_NAME        "ngx_mruby"
#define MODULE_VERSION     "0.0.1"

extern ngx_module_t  ngx_http_mruby_module;

typedef struct ngx_http_mruby_loc_conf_t {
    ngx_mrb_state_t *post_read_state;
    ngx_mrb_state_t *server_rewrite_state;
    ngx_mrb_state_t *rewrite_state;
    ngx_mrb_state_t *access_state;
    ngx_mrb_state_t *handler_state;
    ngx_mrb_state_t *log_handler_state;
    ngx_mrb_state_t *post_read_inline_state;
    ngx_mrb_state_t *server_rewrite_inline_state;
    ngx_mrb_state_t *rewrite_inline_state;
    ngx_mrb_state_t *access_inline_state;
    ngx_mrb_state_t *content_inline_state;
    ngx_mrb_state_t *log_inline_state;
    ngx_flag_t       cached;
} ngx_http_mruby_loc_conf_t;

#endif // NGX_HTTP_MRUBY_MODULE_H
