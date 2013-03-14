/**
 * Copyright (c) 2013 Tatsuhiko Kubo <cubicdaiya@gmail.com>
 */

#include "ngx_http_mruby_handler.h"

#define NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(cached, state, reinit)     \
    do {                                                                \
        if (!cached) {                                                  \
            if (state == NGX_CONF_UNSET_PTR) {                          \
                return NGX_DECLINED;                                    \
            }                                                           \
            if (reinit(state) == NGX_ERROR) {                           \
                return NGX_ERROR;                                       \
            }                                                           \
        }                                                               \
    } while(0)

static ngx_int_t ngx_http_mruby_state_reinit_from_file(ngx_mrb_state_t *state);

static ngx_int_t ngx_http_mruby_state_reinit_from_file(ngx_mrb_state_t *state)
{
    if (state == NGX_CONF_UNSET_PTR) {
        return NGX_ERROR;
    }
    if (ngx_mrb_init_file(state->code.file, ngx_strlen(state->code.file), state) != NGX_OK) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t ngx_http_mruby_post_read_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(
        clcf->cached, 
        clcf->post_read_state,
        ngx_http_mruby_state_reinit_from_file
    );
    return ngx_mrb_run(r, clcf->post_read_state);
}

ngx_int_t ngx_http_mruby_server_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(
        clcf->cached, 
        clcf->server_rewrite_state,
        ngx_http_mruby_state_reinit_from_file
    );
    return ngx_mrb_run(r, clcf->server_rewrite_state);
}

ngx_int_t ngx_http_mruby_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(
        clcf->cached, 
        clcf->rewrite_state,
        ngx_http_mruby_state_reinit_from_file
    );
    return ngx_mrb_run(r, clcf->rewrite_state);
}

ngx_int_t ngx_http_mruby_access_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(
        clcf->cached, 
        clcf->access_state,
        ngx_http_mruby_state_reinit_from_file
    );
    return ngx_mrb_run(r, clcf->access_state);
}

ngx_int_t ngx_http_mruby_content_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(
        clcf->cached, 
        clcf->handler_state,
        ngx_http_mruby_state_reinit_from_file
    );
    return ngx_mrb_run(r, clcf->handler_state);
}

ngx_int_t ngx_http_mruby_log_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(
        clcf->cached, 
        clcf->log_handler_state,
        ngx_http_mruby_state_reinit_from_file
    );
    return ngx_mrb_run(r, clcf->log_handler_state);
}

ngx_int_t ngx_http_mruby_post_read_inline_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    return ngx_mrb_run(r, clcf->post_read_inline_state);
}

ngx_int_t ngx_http_mruby_server_rewrite_inline_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    return ngx_mrb_run(r, clcf->server_rewrite_inline_state);
}

ngx_int_t ngx_http_mruby_rewrite_inline_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    return ngx_mrb_run(r, clcf->rewrite_inline_state);
}

ngx_int_t ngx_http_mruby_access_inline_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    return ngx_mrb_run(r, clcf->access_inline_state);
}

ngx_int_t ngx_http_mruby_content_inline_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    return ngx_mrb_run(r, clcf->content_inline_state);
}

ngx_int_t ngx_http_mruby_log_inline_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    return ngx_mrb_run(r, clcf->log_inline_state);
}
