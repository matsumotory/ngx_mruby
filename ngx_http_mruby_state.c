/*
// ngx_http_mruby_state.c - ngx_mruby mruby state functions
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_state.h"
#include "ngx_http_mruby_module.h"

#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/compile.h>
#include <mruby/string.h>

static ngx_int_t ngx_mrb_init_file(char *code_file_path, size_t len, ngx_mrb_state_t *state)
{
    FILE *mrb_file;
    mrb_state *mrb;
    struct mrb_parser_state *p;

    if ((mrb_file = fopen((char *)code_file_path, "r")) == NULL) {
        return NGX_ERROR;
    }

    mrb = mrb_open();
    ngx_mrb_class_init(mrb);

    state->ai  = mrb_gc_arena_save(mrb);
    p          = mrb_parse_file(mrb, mrb_file, NULL);
    state->mrb = mrb;
    state->n   = mrb_generate_code(mrb, p);

    ngx_cpystrn((u_char *)state->code.file, (u_char *)code_file_path, len + 1);
    state->code_type = NGX_MRB_CODE_TYPE_FILE;
    mrb_pool_close(p->pool);
    fclose(mrb_file);

    return NGX_OK;
}

static ngx_int_t ngx_mrb_init_string(char *code, ngx_mrb_state_t *state)
{
    mrb_state *mrb;
    struct mrb_parser_state *p;

    mrb = mrb_open();
    ngx_mrb_class_init(mrb);

    state->ai   = mrb_gc_arena_save(mrb);
    p           = mrb_parse_string(mrb, code, NULL);
    state->mrb  = mrb;
    state->n    = mrb_generate_code(mrb, p);

    state->code_type = NGX_MRB_CODE_TYPE_STRING;
    mrb_pool_close(p->pool);

    return NGX_OK;
}

ngx_int_t ngx_http_mruby_state_reinit_from_file(ngx_mrb_state_t *state)
{
    if (state == NGX_CONF_UNSET_PTR) {
        return NGX_ERROR;
    }
    if (ngx_mrb_init_file(state->code.file, ngx_strlen(state->code.file), state) != NGX_OK) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

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
