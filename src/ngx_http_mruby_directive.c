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

char *ngx_http_mruby_post_read_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_http_mruby_loc_conf_t *flcf;
    ngx_str_t *value;
    ngx_mrb_code_t *code;

    flcf = conf;

    value = cf->args->elts;
    code  = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    flcf->post_read_code = code;
    ngx_http_mruby_shared_state_compile(mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_server_rewrite_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *flcf;
    ngx_mrb_code_t *code;

    flcf = conf;

    value = cf->args->elts;
    code = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    flcf->server_rewrite_code = code;
    ngx_http_mruby_shared_state_compile(mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_rewrite_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *flcf = conf;
    ngx_mrb_code_t *code;
 
    value = cf->args->elts;
    code = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    flcf->rewrite_code = code;
    ngx_http_mruby_shared_state_compile(mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_access_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *flcf = conf;
    ngx_mrb_code_t *code;
 
    value = cf->args->elts;
    code = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    flcf->access_code = code;
    ngx_http_mruby_shared_state_compile(mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_content_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *flcf = conf;
    ngx_mrb_code_t *code;

    value = cf->args->elts;
    code = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    flcf->handler_code = code;
    ngx_http_mruby_shared_state_compile(mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_log_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *flcf = conf;
    ngx_mrb_code_t *code;

    value = cf->args->elts;
    code = ngx_http_mruby_mrb_code_from_file(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    flcf->log_handler_code = code;
    ngx_http_mruby_shared_state_compile(mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_post_read_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_mrb_code_t *code;
    ngx_http_mruby_loc_conf_t *flcf = conf;

    value = cf->args->elts;
    code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    flcf->post_read_inline_code = code;
    ngx_http_mruby_shared_state_compile(mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_server_rewrite_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_mrb_code_t *code;
    ngx_http_mruby_loc_conf_t *flcf = conf;

    value = cf->args->elts;
    code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    flcf->server_rewrite_inline_code = code;
    ngx_http_mruby_shared_state_compile(mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_rewrite_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_mrb_code_t *code;
    ngx_http_mruby_loc_conf_t *flcf = conf;

    value = cf->args->elts;
    code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    flcf->rewrite_inline_code = code;
    ngx_http_mruby_shared_state_compile(mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_access_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_mrb_code_t *code;
    ngx_http_mruby_loc_conf_t *flcf = conf;

    value = cf->args->elts;
    code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    flcf->access_inline_code = code;
    ngx_http_mruby_shared_state_compile(mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_content_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_mrb_code_t *code;
    ngx_http_mruby_loc_conf_t *flcf = conf;

    value = cf->args->elts;
    code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    flcf->content_inline_code = code;
    ngx_http_mruby_shared_state_compile(mmcf->state, code);

    return NGX_CONF_OK;
}

char *ngx_http_mruby_log_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mruby_main_conf_t *mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mruby_module);
    ngx_str_t *value;
    ngx_mrb_code_t *code;
    ngx_http_mruby_loc_conf_t *flcf = conf;

    value = cf->args->elts;
    code = ngx_http_mruby_mrb_code_from_string(cf->pool, &value[1]);
    if (code == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    flcf->log_inline_code = code;
    ngx_http_mruby_shared_state_compile(mmcf->state, code);

    return NGX_CONF_OK;
}

#if defined(NDK) && NDK

static char *ngx_http_mruby_set_inner(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, code_type_t type)
{
    ngx_str_t  target;
    ngx_str_t *value;
    ndk_set_var_t filter;
    ngx_http_mruby_set_var_data_t *filter_data;

    value  = cf->args->elts;
    target = value[1];

    filter.type = NDK_SET_VAR_MULTI_VALUE_DATA;
    filter.func = cmd->post;
    filter.size = cf->args->nelts - 3;

    filter_data = ngx_pcalloc(cf->pool, sizeof(ngx_http_mruby_set_var_data_t));
    if (filter_data == NULL) {
        return NGX_CONF_ERROR;
    }
    filter_data->state = ngx_pcalloc(cf->pool, sizeof(ngx_mrb_state_t));
    if (filter_data->state == NULL) {
        return NULL;
    }
    filter_data->size   = filter.size;
    filter_data->script = value[2];
    if (type == NGX_MRB_CODE_TYPE_FILE) {
        filter_data->code  = ngx_http_mruby_mrb_code_from_file(cf->pool, &filter_data->script);
        if (ngx_mrb_init_file(&filter_data->script, filter_data->state, filter_data->code) == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }
    } else {
        filter_data->code = ngx_http_mruby_mrb_code_from_string(cf->pool, &filter_data->script);
        ngx_mrb_init_string(&filter_data->script, filter_data->state, filter_data->code);
    } 
    if (filter_data->code == NGX_CONF_UNSET_PTR) {
        if (type == NGX_MRB_CODE_TYPE_FILE) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                               "failed to load mruby script: %s %s:%d", 
                               filter_data->script.data, __FUNCTION__, __LINE__);
        }
        return NGX_CONF_ERROR;
    }

    filter.data = filter_data;

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
