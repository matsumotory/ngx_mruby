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

#define NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(handler_name, code)         \
ngx_int_t ngx_http_mruby_##handler_name##_handler(ngx_http_request_t *r) \
{                                                                       \
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module); \
    ngx_http_mruby_loc_conf_t  *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module); \
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(                               \
        clcf->cached,                                                   \
        mmcf->state,                                                    \
        code,                                                           \
        ngx_http_mruby_state_reinit_from_file                           \
    );                                                                  \
    return ngx_mrb_run(r, mmcf->state, code, clcf->cached);             \
}

#define NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(handler_name, code)  \
ngx_int_t ngx_http_mruby_##handler_name##_inline_handler(ngx_http_request_t *r) \
{                                                                       \
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module); \
    ngx_http_mruby_loc_conf_t  *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module); \
    return ngx_mrb_run(r, mmcf->state, code, 1);                        \
}

NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(post_read,      clcf->post_read_code)
NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(server_rewrite, clcf->server_rewrite_code)
NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(rewrite,        clcf->rewrite_code)
NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(access,         clcf->access_code)
NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(content,        clcf->content_code)
NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(log,            clcf->log_code)

NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(post_read,      clcf->post_read_inline_code)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(server_rewrite, clcf->server_rewrite_inline_code)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(rewrite,        clcf->rewrite_inline_code)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(access,         clcf->access_inline_code)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(content,        clcf->content_inline_code)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(log,            clcf->log_inline_code)

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
