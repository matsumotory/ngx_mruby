/**
 * Copyright (c) 2013 Tatsuhiko Kubo <cubicdaiya@gmail.com>
 */

#include "ngx_http_mruby_hook.h"
#include "ngx_http_mruby_module.h"

static ngx_mrb_state_t *ngx_http_mruby_mrb_state_from_file(ngx_pool_t *pool, ngx_str_t *value);
static ngx_mrb_state_t *ngx_http_mruby_mrb_state_from_string(ngx_pool_t *pool, ngx_str_t *code);

static ngx_mrb_state_t *ngx_http_mruby_mrb_state_from_file(ngx_pool_t *pool, ngx_str_t *code_file_path)
{
    ngx_mrb_state_t *state;
    size_t len;

    state = ngx_pcalloc(pool, sizeof(*state));
    if (state == NULL) {
        return NGX_CONF_UNSET_PTR;
    }

    len = ngx_strlen((char *)code_file_path->data);
    state->code.file = ngx_pcalloc(pool, len + 1);
    if (state->code.file == NULL) {
        return NGX_CONF_UNSET_PTR;
    }

    if (ngx_mrb_init_file((char *)code_file_path->data, len ,state) != NGX_OK) {
        return NGX_CONF_UNSET_PTR;
    }
    return state;
}

static ngx_mrb_state_t *ngx_http_mruby_mrb_state_from_string(ngx_pool_t *pool, ngx_str_t *code)
{
    ngx_mrb_state_t *state;
    size_t len;

    state = ngx_pcalloc(pool, sizeof(*state));
    if (state == NULL) {
        return NGX_CONF_UNSET_PTR;
    }

    len = ngx_strlen(code->data);
    state->code.string = ngx_pcalloc(pool, len + 1);
    if (state->code.string == NULL) {
        return NGX_CONF_UNSET_PTR;
    }
    ngx_cpystrn((u_char *)state->code.string, code->data, len + 1);
    if (ngx_mrb_init_string((char *)code->data, state) != NGX_OK) {
        return NGX_CONF_UNSET_PTR;
    }
    return state;
}

char * ngx_http_mruby_post_read_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *flcf = conf;
    ngx_mrb_state_t *state;

    value = cf->args->elts;
    state = ngx_http_mruby_mrb_state_from_file(cf->pool, &value[1]);
    if (state == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    flcf->post_read_state = state;

    return NGX_CONF_OK;
}

char * ngx_http_mruby_server_rewrite_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *flcf = conf;
    ngx_mrb_state_t *state;

    value = cf->args->elts;
    state = ngx_http_mruby_mrb_state_from_file(cf->pool, &value[1]);
    if (state == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    flcf->server_rewrite_state = state;

    return NGX_CONF_OK;
}

char * ngx_http_mruby_rewrite_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *flcf = conf;
    ngx_mrb_state_t *state;
 
    value = cf->args->elts;
    state = ngx_http_mruby_mrb_state_from_file(cf->pool, &value[1]);
    if (state == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    flcf->rewrite_state = state;

    return NGX_CONF_OK;
}

char * ngx_http_mruby_access_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *flcf = conf;
    ngx_mrb_state_t *state;
 
    value = cf->args->elts;
    state = ngx_http_mruby_mrb_state_from_file(cf->pool, &value[1]);
    if (state == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    flcf->access_state = state;

    return NGX_CONF_OK;
}

char * ngx_http_mruby_content_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *flcf = conf;
    ngx_mrb_state_t *state;

    value = cf->args->elts;
    state = ngx_http_mruby_mrb_state_from_file(cf->pool, &value[1]);
    if (state == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    flcf->handler_state = state;

    return NGX_CONF_OK;
}

char * ngx_http_mruby_log_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *flcf = conf;
    ngx_mrb_state_t *state;

    value = cf->args->elts;
    state = ngx_http_mruby_mrb_state_from_file(cf->pool, &value[1]);
    if (state == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mrb_file(%s) open failed", value[1].data);
        return NGX_CONF_ERROR;
    }
    flcf->log_handler_state = state;

    return NGX_CONF_OK;
}

char * ngx_http_mruby_post_read_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_mrb_state_t *state;
    ngx_http_mruby_loc_conf_t *flcf = conf;

    value = cf->args->elts;
    state = ngx_http_mruby_mrb_state_from_string(cf->pool, &value[1]);
    if (state == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    flcf->post_read_inline_state = state;

    return NGX_CONF_OK;
}

char * ngx_http_mruby_server_rewrite_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_mrb_state_t *state;
    ngx_http_mruby_loc_conf_t *flcf = conf;

    value = cf->args->elts;
    state = ngx_http_mruby_mrb_state_from_string(cf->pool, &value[1]);
    if (state == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    flcf->server_rewrite_inline_state = state;

    return NGX_CONF_OK;
}

char * ngx_http_mruby_rewrite_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_mrb_state_t *state;
    ngx_http_mruby_loc_conf_t *flcf = conf;

    value = cf->args->elts;
    state = ngx_http_mruby_mrb_state_from_string(cf->pool, &value[1]);
    if (state == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    flcf->rewrite_inline_state = state;

    return NGX_CONF_OK;
}

char * ngx_http_mruby_access_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_mrb_state_t *state;
    ngx_http_mruby_loc_conf_t *flcf = conf;

    value = cf->args->elts;
    state = ngx_http_mruby_mrb_state_from_string(cf->pool, &value[1]);
    if (state == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    flcf->access_inline_state = state;

    return NGX_CONF_OK;
}

char * ngx_http_mruby_content_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_mrb_state_t *state;
    ngx_http_mruby_loc_conf_t *flcf = conf;

    value = cf->args->elts;
    state = ngx_http_mruby_mrb_state_from_string(cf->pool, &value[1]);
    if (state == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    flcf->content_inline_state = state;

    return NGX_CONF_OK;
}

char * ngx_http_mruby_log_inline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_mrb_state_t *state;
    ngx_http_mruby_loc_conf_t *flcf = conf;

    value = cf->args->elts;
    state = ngx_http_mruby_mrb_state_from_string(cf->pool, &value[1]);
    if (state == NGX_CONF_UNSET_PTR) {
        return NGX_CONF_ERROR;
    }
    flcf->log_inline_state = state;

    return NGX_CONF_OK;
}
