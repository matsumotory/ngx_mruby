/*
// ngx_http_mruby_handler.c - ngx_mruby mruby handler functions
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_handler.h"
#include "ngx_http_mruby_state.h"

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

ngx_int_t ngx_http_mruby_post_read_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(
        clcf->cached, 
        clcf->post_read_state,
        ngx_http_mruby_state_reinit_from_file
    );
    return ngx_mrb_run(r, clcf->post_read_state, clcf->cached);
}

ngx_int_t ngx_http_mruby_server_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(
        clcf->cached, 
        clcf->server_rewrite_state,
        ngx_http_mruby_state_reinit_from_file
    );
    return ngx_mrb_run(r, clcf->server_rewrite_state, clcf->cached);
}

ngx_int_t ngx_http_mruby_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(
        clcf->cached, 
        clcf->rewrite_state,
        ngx_http_mruby_state_reinit_from_file
    );
    return ngx_mrb_run(r, clcf->rewrite_state, clcf->cached);
}

ngx_int_t ngx_http_mruby_access_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(
        clcf->cached, 
        clcf->access_state,
        ngx_http_mruby_state_reinit_from_file
    );
    return ngx_mrb_run(r, clcf->access_state, clcf->cached);
}

ngx_int_t ngx_http_mruby_content_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(
        clcf->cached, 
        clcf->handler_state,
        ngx_http_mruby_state_reinit_from_file
    );
    return ngx_mrb_run(r, clcf->handler_state, clcf->cached);
}

ngx_int_t ngx_http_mruby_log_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(
        clcf->cached, 
        clcf->log_handler_state,
        ngx_http_mruby_state_reinit_from_file
    );
    return ngx_mrb_run(r, clcf->log_handler_state, clcf->cached);
}

ngx_int_t ngx_http_mruby_post_read_inline_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    return ngx_mrb_run(r, clcf->post_read_inline_state, 1);
}

ngx_int_t ngx_http_mruby_server_rewrite_inline_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    return ngx_mrb_run(r, clcf->server_rewrite_inline_state, 1);
}

ngx_int_t ngx_http_mruby_rewrite_inline_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    return ngx_mrb_run(r, clcf->rewrite_inline_state, 1);
}

ngx_int_t ngx_http_mruby_access_inline_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    return ngx_mrb_run(r, clcf->access_inline_state, 1);
}

ngx_int_t ngx_http_mruby_content_inline_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    return ngx_mrb_run(r, clcf->content_inline_state, 1);
}

ngx_int_t ngx_http_mruby_log_inline_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    return ngx_mrb_run(r, clcf->log_inline_state, 1);
}

#if defined(NDK) && NDK
ngx_int_t ngx_http_mruby_set_handler(ngx_http_request_t *r, ngx_str_t *val,
                                     ngx_http_variable_value_t *v, void *data)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    ngx_http_mruby_set_var_data_t *filter_data;

    filter_data = data;
    if (!clcf->cached && ngx_http_mruby_state_reinit_from_file(filter_data->state)) {
        return NGX_ERROR;
    }
 
    return ngx_mrb_run_args(r, filter_data->state, clcf->cached, v, filter_data->size, val);
}

ngx_int_t ngx_http_mruby_set_inline_handler(ngx_http_request_t *r, ngx_str_t *val,
                                            ngx_http_variable_value_t *v, void *data)
{
    ngx_http_mruby_set_var_data_t *filter_data;
    filter_data = data;
    return ngx_mrb_run_args(r, filter_data->state, 1, v, filter_data->size, val);
}
#endif


