/*
// ngx_http_mruby_state.c - ngx_mruby mruby state functions
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_state.h"
#include "ngx_http_mruby_module.h"
#include "ngx_http_mruby_request.h"

#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/compile.h>
#include <mruby/string.h>

ngx_int_t ngx_mrb_init_file(ngx_str_t *script_file_path, ngx_mrb_state_t *state, ngx_mrb_code_t *code)
{
    FILE *mrb_file;
    mrb_state *mrb;
    struct mrb_parser_state *p;

    if ((mrb_file = fopen((char *)script_file_path->data, "r")) == NULL) {
        return NGX_ERROR;
    }

    mrb = mrb_open();
    ngx_mrb_class_init(mrb);

    state->ai  = mrb_gc_arena_save(mrb);
    p          = mrb_parse_file(mrb, mrb_file, NULL);
    state->mrb = mrb;
    code->n    = mrb_generate_code(mrb, p);

    mrb_pool_close(p->pool);
    fclose(mrb_file);

    return NGX_OK;
}

ngx_int_t ngx_mrb_init_string(ngx_str_t *script, ngx_mrb_state_t *state, ngx_mrb_code_t *code)
{
    mrb_state *mrb;
    struct mrb_parser_state *p;

    mrb = mrb_open();
    ngx_mrb_class_init(mrb);

    state->ai   = mrb_gc_arena_save(mrb);
    p           = mrb_parse_string(mrb, (char *)script->data, NULL);
    state->mrb  = mrb;
    code->n     = mrb_generate_code(mrb, p);

    mrb_pool_close(p->pool);

    return NGX_OK;
}

static ngx_int_t ngx_mrb_gencode_state(ngx_mrb_state_t *state, ngx_mrb_code_t *code)
{
    FILE *mrb_file;
    struct mrb_parser_state *p;

    if ((mrb_file = fopen((char *)code->code.file, "r")) == NULL) {
        return NGX_ERROR;
    }

    state->ai = mrb_gc_arena_save(state->mrb);
    p         = mrb_parse_file(state->mrb, mrb_file, NULL);
    code->n   = mrb_generate_code(state->mrb, p);

    mrb_pool_close(p->pool);
    fclose(mrb_file);

    return NGX_OK;
}

ngx_int_t ngx_http_mruby_state_reinit_from_file(ngx_mrb_state_t *state, ngx_mrb_code_t *code)
{
    if (state == NGX_CONF_UNSET_PTR) {
        return NGX_ERROR;
    }
    if (ngx_mrb_gencode_state(state, code) != NGX_OK) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_mrb_code_t *ngx_http_mruby_mrb_code_from_file(ngx_pool_t *pool, ngx_str_t *code_file_path)
{
    ngx_mrb_code_t *code;
    size_t len;

    code = ngx_pcalloc(pool, sizeof(*code));
    if (code == NULL) {
        return NGX_CONF_UNSET_PTR;
    }

    len = ngx_strlen((char *)code_file_path->data);
    code->code.file = ngx_pcalloc(pool, len + 1);
    if (code->code.file == NULL) {
        return NGX_CONF_UNSET_PTR;
    }
    ngx_cpystrn((u_char *)code->code.file, (u_char *)code_file_path->data, code_file_path->len + 1);
    code->code_type = NGX_MRB_CODE_TYPE_FILE;
    return code;
}

ngx_mrb_code_t *ngx_http_mruby_mrb_code_from_string(ngx_pool_t *pool, ngx_str_t *code_s)
{
    ngx_mrb_code_t *code;
    size_t len;

    code = ngx_pcalloc(pool, sizeof(*code));
    if (code == NULL) {
        return NGX_CONF_UNSET_PTR;
    }

    len = ngx_strlen(code_s->data);
    code->code.string = ngx_pcalloc(pool, len + 1);
    if (code->code.string == NULL) {
        return NGX_CONF_UNSET_PTR;
    }
    ngx_cpystrn((u_char *)code->code.string, code_s->data, len + 1);
    code->code_type = NGX_MRB_CODE_TYPE_STRING;
    return code;
}

ngx_int_t ngx_http_mruby_shared_state_init(ngx_mrb_state_t *state)
{
    mrb_state *mrb;

    mrb = mrb_open();
    ngx_mrb_class_init(mrb);

    state->mrb = mrb;

    return NGX_OK;
}

ngx_int_t ngx_http_mruby_shared_state_compile(ngx_conf_t *cf, ngx_mrb_state_t *state, ngx_mrb_code_t *code)
{
    FILE *mrb_file;
    struct mrb_parser_state *p;

    if (code->code_type == NGX_MRB_CODE_TYPE_FILE) {
        if ((mrb_file = fopen((char *)code->code.file, "r")) == NULL) {
            return NGX_ERROR;
        }
        p = mrb_parse_file(state->mrb, mrb_file, NULL);
        fclose(mrb_file);
    } else {
        p = mrb_parse_string(state->mrb, (char *)code->code.string, NULL);
    }

    code->n = mrb_generate_code(state->mrb, p);
    mrb_pool_close(p->pool);

    if (code->code_type == NGX_MRB_CODE_TYPE_FILE) {
        ngx_conf_log_error(NGX_LOG_NOTICE
            , cf
            , 0
            , "%s NOTICE %s:%d: compile info: code->n=%d code->code.file=(%s)"
            , MODULE_NAME
            , __func__
            , __LINE__
            , code->n
            , code->code.file
        );
    } else {
        ngx_conf_log_error(NGX_LOG_NOTICE
            , cf
            , 0
            , "%s NOTICE %s:%d: compile info: code->n=%d code->code.string"
            , MODULE_NAME
            , __func__
            , __LINE__
            , code->n
        );
    }

    return NGX_OK;
}

