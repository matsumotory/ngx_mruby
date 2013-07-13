/*
// ngx_http_mruby_handler.c - ngx_mruby mruby handler functions
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_handler.h"
#include "ngx_http_mruby_state.h"

#define NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(cached, state, code, reinit) \
    do {                                                                \
        if (!cached) {                                                  \
            if (state == NGX_CONF_UNSET_PTR) {                          \
                return NGX_DECLINED;                                    \
            }                                                           \
            if (code == NGX_CONF_UNSET_PTR) {                           \
                return NGX_DECLINED;                                    \
            }                                                           \
            if (reinit(state, code) == NGX_ERROR) {                     \
                return NGX_ERROR;                                       \
            }                                                           \
        }                                                               \
    } while(0)

ngx_int_t ngx_http_mruby_post_read_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
    ngx_http_mruby_loc_conf_t  *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(
        clcf->cached, 
        mmcf->state,
        clcf->post_read_code,
        ngx_http_mruby_state_reinit_from_file
    );
    return ngx_mrb_run(r, mmcf->state, clcf->post_read_code, clcf->cached);
}

ngx_int_t ngx_http_mruby_server_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
    ngx_http_mruby_loc_conf_t  *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(
        clcf->cached, 
        mmcf->state,
        clcf->server_rewrite_code,
        ngx_http_mruby_state_reinit_from_file
    );
    return ngx_mrb_run(r, mmcf->state, clcf->server_rewrite_code, clcf->cached);
}

ngx_int_t ngx_http_mruby_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
    ngx_http_mruby_loc_conf_t  *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(
        clcf->cached, 
        mmcf->state,
        clcf->rewrite_code,
        ngx_http_mruby_state_reinit_from_file
    );
    return ngx_mrb_run(r, mmcf->state, clcf->rewrite_code, clcf->cached);
}

ngx_int_t ngx_http_mruby_access_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
    ngx_http_mruby_loc_conf_t  *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(
        clcf->cached, 
        mmcf->state,
        clcf->access_code,
        ngx_http_mruby_state_reinit_from_file
    );
    return ngx_mrb_run(r, mmcf->state, clcf->access_code, clcf->cached);
}

ngx_int_t ngx_http_mruby_content_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
    ngx_http_mruby_loc_conf_t  *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(
        clcf->cached, 
        mmcf->state,
        clcf->handler_code,
        ngx_http_mruby_state_reinit_from_file
    );
    return ngx_mrb_run(r, mmcf->state, clcf->handler_code, clcf->cached);
}

ngx_int_t ngx_http_mruby_log_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
    ngx_http_mruby_loc_conf_t  *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(
        clcf->cached, 
        mmcf->state,
        clcf->log_handler_code,
        ngx_http_mruby_state_reinit_from_file
    );
    return ngx_mrb_run(r, mmcf->state, clcf->log_handler_code, clcf->cached);
}

ngx_int_t ngx_http_mruby_post_read_inline_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
    ngx_http_mruby_loc_conf_t  *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    return ngx_mrb_run(r, mmcf->state, clcf->post_read_inline_code, 1);
}

ngx_int_t ngx_http_mruby_server_rewrite_inline_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
    ngx_http_mruby_loc_conf_t  *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    return ngx_mrb_run(r, mmcf->state, clcf->server_rewrite_inline_code, 1);
}

ngx_int_t ngx_http_mruby_rewrite_inline_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
    ngx_http_mruby_loc_conf_t  *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    return ngx_mrb_run(r, mmcf->state, clcf->rewrite_inline_code, 1);
}

ngx_int_t ngx_http_mruby_access_inline_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
    ngx_http_mruby_loc_conf_t  *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    return ngx_mrb_run(r, mmcf->state, clcf->access_inline_code, 1);
}

ngx_int_t ngx_http_mruby_content_inline_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
    ngx_http_mruby_loc_conf_t  *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    return ngx_mrb_run(r, mmcf->state, clcf->content_inline_code, 1);
}

ngx_int_t ngx_http_mruby_log_inline_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
    ngx_http_mruby_loc_conf_t  *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    return ngx_mrb_run(r, mmcf->state, clcf->log_inline_code, 1);
}

#if defined(NDK) && NDK
ngx_int_t ngx_http_mruby_set_handler(ngx_http_request_t *r, ngx_str_t *val,
                                     ngx_http_variable_value_t *v, void *data)
{
    ngx_http_mruby_loc_conf_t  *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    ngx_http_mruby_set_var_data_t *filter_data;

    filter_data = data;
    if (!clcf->cached && ngx_http_mruby_state_reinit_from_file(filter_data->state, filter_data->code)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "failed to load mruby script: %s %s:%d", 
                      filter_data->script.data, __FUNCTION__, __LINE__);
        return NGX_ERROR;
    }
 
    return ngx_mrb_run_args(r, filter_data->state, filter_data->code, clcf->cached, v, filter_data->size, val);
}

ngx_int_t ngx_http_mruby_set_inline_handler(ngx_http_request_t *r, ngx_str_t *val,
                                            ngx_http_variable_value_t *v, void *data)
{
    ngx_http_mruby_set_var_data_t *filter_data;
    filter_data = data;
    return ngx_mrb_run_args(r, filter_data->state, filter_data->code, 1, v, filter_data->size, val);
}
#endif
