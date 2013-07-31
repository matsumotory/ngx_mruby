/*
// ngx_http_mruby_directive.c - ngx_mruby mruby directive functions
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_state.h"
#include "ngx_http_mruby_directive.h"
#include "ngx_http_mruby_module.h"

#if defined(NDK) && NDK
static char *ngx_http_mruby_set_inner(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, code_type_t type);
#endif

char *ngx_http_mruby_init_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_mrb_code_t *code;

    if (mmcf->init_code != NULL) {
        return "[Use either 'mruby_init' or 'mruby_init_inline']";
    }

    value = cf->args->elts;

    code = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    mmcf->init_code = code;
    ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_init_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_mrb_code_t *code;

    if (mmcf->init_code != NULL) {
        return "is duplicated";
    }

    value = cf->args->elts;

    code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    mmcf->init_code = code;
    ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_post_read_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_http_mruby_loc_conf_t *mlcf;
    ngx_str_t *value;
    ngx_mrb_code_t *code;

    mlcf = conf;

    value = cf->args->elts;
    code  = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    mlcf->post_read_code = code;
    ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_server_rewrite_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *mlcf;
    ngx_mrb_code_t *code;

    mlcf = conf;

    value = cf->args->elts;
    code  = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    mlcf->server_rewrite_code = code;
    ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_rewrite_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *mlcf = conf;
    ngx_mrb_code_t *code;
 
    value = cf->args->elts;
    code  = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    mlcf->rewrite_code = code;
    ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_access_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *mlcf = conf;
    ngx_mrb_code_t *code;
 
    value = cf->args->elts;
    code  = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    mlcf->access_code = code;
    ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_content_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *mlcf = conf;
    ngx_mrb_code_t *code;

    value = cf->args->elts;
    code  = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    mlcf->content_code = code;
    ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_log_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *mlcf = conf;
    ngx_mrb_code_t *code;

    value = cf->args->elts;
    code  = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    mlcf->log_code = code;
    ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_post_read_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_mrb_code_t *code;
    ngx_http_mruby_loc_conf_t *mlcf = conf;

    value = cf->args->elts;
    code  = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    mlcf->post_read_inline_code = code;
    ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_server_rewrite_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_mrb_code_t *code;
    ngx_http_mruby_loc_conf_t *mlcf = conf;

    value = cf->args->elts;
    code  = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    mlcf->server_rewrite_inline_code = code;
    ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_rewrite_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_mrb_code_t *code;
    ngx_http_mruby_loc_conf_t *mlcf = conf;

    value = cf->args->elts;
    code  = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    mlcf->rewrite_inline_code = code;
    ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_access_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_mrb_code_t *code;
    ngx_http_mruby_loc_conf_t *mlcf = conf;

    value = cf->args->elts;
    code  = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    mlcf->access_inline_code = code;
    ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_content_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_mrb_code_t *code;
    ngx_http_mruby_loc_conf_t *mlcf = conf;

    value = cf->args->elts;
    code  = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    mlcf->content_inline_code = code;
    ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_log_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_mrb_code_t *code;
    ngx_http_mruby_loc_conf_t *mlcf = conf;

    value = cf->args->elts;
    code  = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    mlcf->log_inline_code = code;
    ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_header_filter_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *mlcf = conf;
    ngx_mrb_code_t *code;

    value = cf->args->elts;
    code  = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    mlcf->header_filter_code = code;
    ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
    mmcf->enabled_header_filter = 1;
    mlcf->header_filter_handler = cmd->post;

    return NGX_CONF_OK;
}

char *ngx_http_mruby_body_filter_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *mlcf = conf;
    ngx_mrb_code_t *code;

    value = cf->args->elts;
    code  = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    mlcf->body_filter_code = code;
    ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
    mmcf->enabled_header_filter = 1;
    mmcf->enabled_body_filter   = 1;
    mlcf->body_filter_handler   = cmd->post;

    return NGX_CONF_OK;
}

char *ngx_http_mruby_header_filter_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_mrb_code_t *code;
    ngx_http_mruby_loc_conf_t *mlcf = conf;

    value = cf->args->elts;
    code  = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    mlcf->header_filter_inline_code = code;
    ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
    mmcf->enabled_header_filter = 1;
    mlcf->header_filter_handler = cmd->post;

    return NGX_CONF_OK;
}

char *ngx_http_mruby_body_filter_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_mrb_code_t *code;
    ngx_http_mruby_loc_conf_t *mlcf = conf;

    value = cf->args->elts;
    code  = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    mlcf->body_filter_inline_code = code;
    ngx_http_mruby_shared_state_compile(cf, mmcf->state, code);
    mmcf->enabled_header_filter = 1;
    mmcf->enabled_body_filter   = 1;
    mlcf->body_filter_handler   = cmd->post;

    return NGX_CONF_OK;
}

#if defined(NDK) && NDK

static char *ngx_http_mruby_set_inner(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, code_type_t type)
{
    ngx_str_t  target;
    ngx_str_t *value;
    ndk_set_var_t filter;
    ngx_http_mruby_set_var_data_t *filter_data;
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);

    value  = cf->args->elts;
    target = value[1];

    filter.type = NDK_SET_VAR_MULTI_VALUE_DATA;
    filter.func = cmd->post;
    filter.size = cf->args->nelts - 3;

    filter_data = ngx_pcalloc(cf->pool, sizeof(ngx_http_mruby_set_var_data_t));
    if (filter_data == NULL) {
        return NGX_CONF_ERROR;
    }

    filter_data->state  = mmcf->state;
    filter_data->size   = filter.size;
    filter_data->script = value[2];
    if (type == NGX_MRB_CODE_TYPE_FILE) {
        filter_data->code = ngx_http_mruby_mrb_code_from_file(cf->pool, &filter_data->script);
    } else {
        filter_data->code = ngx_http_mruby_mrb_code_from_string(cf->pool, &filter_data->script);
    } 
    ngx_http_mruby_shared_state_compile(cf, filter_data->state, filter_data->code);
    if (filter_data->code == NGX_CONF_UNSET_PTR) {
        if (type == NGX_MRB_CODE_TYPE_FILE) {
            ngx_conf_log_error(NGX_LOG_ERR
                , cf
                , 0
                , "failed to load mruby script: %s %s:%d"
                , filter_data->script.data
                , __FUNCTION__
                , __LINE__
                , target.data
                , filter_data->script.data
            );
        }
        return NGX_CONF_ERROR;
    }

    filter.data = filter_data;
    ngx_conf_log_error(NGX_LOG_NOTICE
        , cf
        , 0
        , "%s NOTICE %s:%d: target variable=(%s) get from irep_n=(%d)"
        , MODULE_NAME
        , __FUNCTION__
        , __LINE__
        , target.data
        , filter_data->code->n
    );

    return ndk_set_var_multi_value_core(cf, &target, &value[3], &filter);
}

char *ngx_http_mruby_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return ngx_http_mruby_set_inner(cf, cmd, conf, NGX_MRB_CODE_TYPE_FILE);
}

char *ngx_http_mruby_set_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return ngx_http_mruby_set_inner(cf, cmd, conf, NGX_MRB_CODE_TYPE_STRING);
}
#endif
