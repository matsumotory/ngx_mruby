/*
// ngx_http_mruby_handler.c - ngx_mruby mruby handler functions
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_handler.h"
#include "ngx_http_mruby_state.h"

#define NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(handler_name, code)                                   \
ngx_int_t ngx_http_mruby_##handler_name##_handler(ngx_http_request_t *r)                          \
{                                                                                                 \
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);   \
    ngx_http_mruby_loc_conf_t  *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);    \
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(                                                         \
        mlcf->cached,                                                                             \
        mmcf->state,                                                                              \
        code,                                                                                     \
        ngx_http_mruby_state_reinit_from_file                                                     \
    );                                                                                            \
    return ngx_mrb_run(r, mmcf->state, code, mlcf->cached, NULL);                                 \
}

NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(post_read,      mlcf->post_read_code)
NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(server_rewrite, mlcf->server_rewrite_code)
NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(rewrite,        mlcf->rewrite_code)
NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(access,         mlcf->access_code)
//NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(content,        mlcf->content_code)
NGX_MRUBY_DEFINE_METHOD_NGX_HANDLER(log,            mlcf->log_code)

ngx_int_t ngx_http_mruby_content_handler(ngx_http_request_t *r)                        
{                                                                                               
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module); 
    ngx_http_mruby_loc_conf_t  *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);  

    ngx_mrb_code_t *code;
    size_t root;
    ngx_str_t path;

    if (mlcf->add_handler) {
        if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
            ngx_log_error(NGX_LOG_ERR
                , r->connection->log
                , 0
                , "%s:%d request_file(%s) map failed"
                , __FUNCTION__
                , __LINE__
                , path.data
            );
            return NGX_ERROR;
        } 
        if (access(path.data, F_OK) != 0) {
            ngx_log_error(NGX_LOG_INFO
                , r->connection->log
                , 0
                , "%s:%d request_file(%s) not found"
                , __FUNCTION__
                , __LINE__
                , path.data
            );
            return NGX_HTTP_NOT_FOUND;
        }
        code  = ngx_http_mruby_mrb_code_from_file(r->pool, &path);
        if (code == NGX_CONF_UNSET_PTR) {
            ngx_log_error(NGX_LOG_ERR
                , r->connection->log
                , 0
                , "%s:%d mrb_file(%s) open failed"
                , __FUNCTION__
                , __LINE__
                , path.data
            );
            return NGX_ERROR;
        }
    } else {
        code = mlcf->content_code;
    }
    NGX_MRUBY_STATE_REINIT_IF_NOT_CACHED(                                                       
        mlcf->cached,                                                                           
        mmcf->state,                                                                            
        code,                                                                                   
        ngx_http_mruby_state_reinit_from_file                                                   
    );                                                                                          
    return ngx_mrb_run(r, mmcf->state, code, mlcf->cached, NULL);                               
}

#define NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(handler_name, code)                            \
ngx_int_t ngx_http_mruby_##handler_name##_inline_handler(ngx_http_request_t *r)                   \
{                                                                                                 \
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);   \
    ngx_http_mruby_loc_conf_t  *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);    \
    return ngx_mrb_run(r, mmcf->state, code, 1, NULL);                                            \
}

NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(post_read,      mlcf->post_read_inline_code)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(server_rewrite, mlcf->server_rewrite_inline_code)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(rewrite,        mlcf->rewrite_inline_code)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(access,         mlcf->access_inline_code)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(content,        mlcf->content_inline_code)
NGX_MRUBY_DEFINE_METHOD_NGX_INLINE_HANDLER(log,            mlcf->log_inline_code)

#if defined(NDK) && NDK
ngx_int_t ngx_http_mruby_set_handler(ngx_http_request_t *r, ngx_str_t *val,
                                     ngx_http_variable_value_t *v, void *data)
{
    ngx_http_mruby_loc_conf_t  *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);
    ngx_http_mruby_set_var_data_t *filter_data;

    filter_data = data;
    if (!mlcf->cached && ngx_http_mruby_state_reinit_from_file(filter_data->state, filter_data->code)) {
        ngx_log_error(NGX_LOG_ERR
            , r->connection->log
            , 0
            , "failed to load mruby script: %s %s:%d"
            , filter_data->script.data
            , __FUNCTION__
            , __LINE__
        );
        return NGX_ERROR;
    }
 
    return ngx_mrb_run(r, filter_data->state, filter_data->code, mlcf->cached, val);
}

ngx_int_t ngx_http_mruby_set_inline_handler(ngx_http_request_t *r, ngx_str_t *val,
                                            ngx_http_variable_value_t *v, void *data)
{
    ngx_http_mruby_set_var_data_t *filter_data;
    filter_data = data;
    return ngx_mrb_run(r, filter_data->state, filter_data->code, 1, val);
}
#endif
