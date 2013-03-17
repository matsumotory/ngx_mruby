/*
// ngx_http_mruby_state.c - ngx_mruby mruby state functions
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_state.h"
#include "ngx_http_mruby_module.h"

ngx_mrb_state_t *ngx_http_mruby_mrb_state_from_file(ngx_pool_t *pool, ngx_str_t *code_file_path)
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

ngx_mrb_state_t *ngx_http_mruby_mrb_state_from_string(ngx_pool_t *pool, ngx_str_t *code)
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
