/*
// ngx_http_mruby_init.c - ngx_mruby mruby init functions
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_core.h"
#include "ngx_http_mruby_init.h"
#include "ngx_http_mruby_request.h"

#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/compile.h>
#include <mruby/string.h>


ngx_int_t ngx_mrb_init_file(char *code_file_path, size_t len, ngx_mrb_state_t *state)
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

    ngx_cpystrn((u_char *)state->file, (u_char *)code_file_path, len + 1);
    mrb_pool_close(p->pool);
    fclose(mrb_file);

    return NGX_OK;
}

ngx_int_t ngx_mrb_init_string(char *code, ngx_mrb_state_t *state)
{
    mrb_state *mrb;
    struct mrb_parser_state *p;

    mrb = mrb_open();
    ngx_mrb_class_init(mrb);

    state->ai   = mrb_gc_arena_save(mrb);
    p           = mrb_parse_string(mrb, code, NULL);
    state->mrb  = mrb;
    state->n    = mrb_generate_code(mrb, p);
    state->file = NGX_CONF_UNSET_PTR;

    mrb_pool_close(p->pool);

    return NGX_OK;
}

ngx_int_t ngx_mrb_class_init(mrb_state *mrb)
{
    struct RClass *class;

    class = mrb_define_module(mrb, "Nginx");

    ngx_mrb_core_init(mrb, class);
    ngx_mrb_request_class_init(mrb, class);

    return NGX_OK;
}
