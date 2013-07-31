/*
// ngx_http_mruby_core.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_module.h"
#include "ngx_http_mruby_core.h"
#include "ngx_http_mruby_request.h"

#include "mruby.h"
#include "mruby/proc.h"
#include "mruby/data.h"
#include "mruby/compile.h"
#include "mruby/string.h"
#include "mruby/array.h"
#include "mruby/variable.h"

#include <nginx.h>
#include <ngx_http.h>
#include <ngx_conf_file.h>
#include <ngx_log.h>
#include <ngx_buf.h>

ngx_module_t  ngx_http_mruby_module;

static void ngx_mrb_raise_error(mrb_state *mrb, mrb_value obj, ngx_http_request_t *r);
static void ngx_mrb_raise_file_error(mrb_state *mrb, mrb_value obj, ngx_http_request_t *r, char *code_file);
static void ngx_mrb_raise_conf_error(mrb_state *mrb, mrb_value obj, ngx_conf_t *cf);
static void ngx_mrb_raise_file_conf_error(mrb_state *mrb, mrb_value obj, ngx_conf_t *cf, char *code_file);

static mrb_value ngx_mrb_send_header(mrb_state *mrb, mrb_value self);
static mrb_value ngx_mrb_rputs(mrb_state *mrb, mrb_value self);
static mrb_value ngx_mrb_redirect(mrb_state *mrb, mrb_value self);

static void ngx_mrb_irep_clean(ngx_mrb_state_t *state, ngx_mrb_code_t *code)
{
    state->mrb->irep_len = code->n;
    mrb_irep_free(state->mrb, state->mrb->irep[code->n]);
    state->mrb->exc = 0;
}

ngx_int_t ngx_mrb_run_conf(ngx_conf_t *cf, ngx_mrb_state_t *state, ngx_mrb_code_t *code)
{
    ngx_log_error(NGX_LOG_INFO
        , cf->log
        , 0
        , "%s INFO %s:%d: mrb_run info: irep_n=%d"
        , MODULE_NAME
        , __func__
        , __LINE__
        , code->n
    );
    mrb_run(state->mrb, mrb_proc_new(state->mrb, state->mrb->irep[code->n]), mrb_top_self(state->mrb));
    if (state->mrb->exc) {
        if (code->code_type == NGX_MRB_CODE_TYPE_FILE) {
            ngx_mrb_raise_file_conf_error(state->mrb, mrb_obj_value(state->mrb->exc), cf, code->code.file);
        } else {
            ngx_mrb_raise_conf_error(state->mrb, mrb_obj_value(state->mrb->exc), cf);
        }
        mrb_gc_arena_restore(state->mrb, state->ai);
        return NGX_ERROR;
    }
    
    mrb_gc_arena_restore(state->mrb, state->ai);
    return NGX_OK;
}

ngx_int_t ngx_mrb_run(ngx_http_request_t *r, ngx_mrb_state_t *state, ngx_mrb_code_t *code, ngx_flag_t cached, ngx_str_t *result)
{
    int result_len;
    mrb_value mrb_result;
    ngx_http_mruby_ctx_t *ctx;
    ngx_mrb_rputs_chain_list_t *chain;

    if (state == NGX_CONF_UNSET_PTR || code == NGX_CONF_UNSET_PTR) {
        return NGX_DECLINED;
    }
    ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);
    if (ctx == NULL && (ctx = ngx_pcalloc(r->pool, sizeof(*ctx))) == NULL) {
        ngx_log_error(NGX_LOG_ERR
            , r->connection->log
            , 0
            , "failed to allocate memory from r->pool %s:%d"
            , __FUNCTION__
            , __LINE__
        );
        return NGX_ERROR;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_mruby_module);
    ngx_mrb_push_request(r);

    if (!cached) {
        state->ai = mrb_gc_arena_save(state->mrb);
    }

    ngx_log_error(NGX_LOG_INFO
        , r->connection->log
        , 0
        , "%s INFO %s:%d: mrb_run info: irep_n=%d arena_idx=%d"
        , MODULE_NAME
        , __func__
        , __LINE__
        , code->n
        , state->ai
    );
    mrb_result = mrb_run(state->mrb, mrb_proc_new(state->mrb, state->mrb->irep[code->n]), mrb_top_self(state->mrb));
    if (state->mrb->exc) {
        if (code->code_type == NGX_MRB_CODE_TYPE_FILE) {
            ngx_mrb_raise_file_error(state->mrb, mrb_obj_value(state->mrb->exc), r, code->code.file);
        } else {
            ngx_mrb_raise_error(state->mrb, mrb_obj_value(state->mrb->exc), r);
        }
    }
    if (result != NULL) {
        if (mrb_nil_p(mrb_result)) { 
            result->data = NULL;
            result->len = 0;
        } else {
            if (mrb_type(mrb_result) != MRB_TT_STRING) {
                mrb_result = mrb_funcall(state->mrb, mrb_result, "to_s", 0, NULL);
            }
            result_len = ngx_strlen((u_char *)RSTRING_PTR(mrb_result));
            result->data = ngx_palloc(r->pool, result_len);
            if (result->data == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(result->data, (u_char *)RSTRING_PTR(mrb_result), result_len);
            result->len  = result_len;
            ngx_log_error(NGX_LOG_INFO
                , r->connection->log
                , 0
                , "%s INFO %s:%d: mrb_run info: irep_n=(%d) return value=(%s)"
                , MODULE_NAME
                , __func__
                , __LINE__
                , code->n
                , RSTRING_PTR(mrb_result)
            );
        }
    }

    mrb_gc_arena_restore(state->mrb, state->ai);

    if (!cached) {
        ngx_mrb_irep_clean(state, code);
    }

    // TODO: Support rputs by multi directive
    if (ngx_http_get_module_ctx(r, ngx_http_mruby_module) != NULL) {
        chain = ctx->rputs_chain;
        if (chain == NULL) {
            ngx_log_error(NGX_LOG_INFO
                , r->connection->log
                , 0
                , "%s INFO %s:%d: mrb_run info: irep_n=(%d) rputs_chain is null and return NGX_OK"
                , MODULE_NAME
                , __func__
                , __LINE__
                , code->n
            );
            return NGX_OK;
        }
        if (r->headers_out.status == NGX_HTTP_OK || !(*chain->last)->buf->last_buf) {
            r->headers_out.status = NGX_HTTP_OK;
            (*chain->last)->buf->last_buf = 1;
            ngx_http_send_header(r);
            ngx_http_output_filter(r, chain->out);
            ngx_http_set_ctx(r, NULL, ngx_http_mruby_module);
            return NGX_OK;
        } else {
            return r->headers_out.status;
        }
    }
    return NGX_OK;
}

ngx_int_t ngx_mrb_run_body_filter(ngx_http_request_t *r, ngx_mrb_state_t *state, ngx_mrb_code_t *code, ngx_flag_t cached, ngx_http_mruby_ctx_t *ctx)
{
    mrb_value ARGV, mrb_result;

    ARGV = mrb_ary_new_capa(state->mrb, 1);

    mrb_ary_push(state->mrb, ARGV, mrb_str_new(state->mrb, (char *)ctx->body, ctx->body_length));
    mrb_define_global_const(state->mrb, "ARGV", ARGV);

    mrb_result = mrb_run(state->mrb, mrb_proc_new(state->mrb, state->mrb->irep[code->n]), mrb_top_self(state->mrb));
    if (state->mrb->exc) {
        if (code->code_type == NGX_MRB_CODE_TYPE_FILE) {
            ngx_mrb_raise_file_error(state->mrb, mrb_obj_value(state->mrb->exc), r, code->code.file);
        } else {
            ngx_mrb_raise_error(state->mrb, mrb_obj_value(state->mrb->exc), r);
        }
        mrb_gc_arena_restore(state->mrb, state->ai);
        if (!cached) {
            ngx_mrb_irep_clean(state, code);
        }
        return NGX_ERROR;
    }
    
    if (mrb_type(mrb_result) != MRB_TT_STRING) {
        mrb_result = mrb_funcall(state->mrb, mrb_result, "to_s", 0, NULL);
    }

    ctx->body        = (u_char *)RSTRING_PTR(mrb_result);
    ctx->body_length = ngx_strlen(ctx->body);

    mrb_gc_arena_restore(state->mrb, state->ai);
    if (!cached) {
        ngx_mrb_irep_clean(state, code);
    }
    return NGX_OK;
}

static void ngx_mrb_raise_error(mrb_state *mrb, mrb_value obj, ngx_http_request_t *r)
{  
    struct RString *str;
    char *err_out;
    
    obj = mrb_funcall(mrb, obj, "inspect", 0);
    if (mrb_type(obj) == MRB_TT_STRING) {
        str = mrb_str_ptr(obj);
        err_out = str->ptr;
        ngx_log_error(NGX_LOG_ERR
            , r->connection->log
            , 0
            , "mrb_run failed. error: %s"
            , err_out
        );
    }
}

static void ngx_mrb_raise_conf_error(mrb_state *mrb, mrb_value obj, ngx_conf_t *cf)
{  
    struct RString *str;
    char *err_out;
    
    obj = mrb_funcall(mrb, obj, "inspect", 0);
    if (mrb_type(obj) == MRB_TT_STRING) {
        str = mrb_str_ptr(obj);
        err_out = str->ptr;
        ngx_conf_log_error(NGX_LOG_ERR
            , cf
            , 0
            , "mrb_run failed. error: %s"
            , err_out
        );
    }
}

static void ngx_mrb_raise_file_error(mrb_state *mrb, mrb_value obj, ngx_http_request_t *r, char *code_file)
{  
    struct RString *str;
    char *err_out;
    
    obj = mrb_funcall(mrb, obj, "inspect", 0);
    if (mrb_type(obj) == MRB_TT_STRING) {
        str = mrb_str_ptr(obj);
        err_out = str->ptr;
        ngx_log_error(NGX_LOG_ERR
            , r->connection->log
            , 0
            , "mrb_run failed. file: %s error: %s"
            , code_file
            , err_out
        );
    }
}

static void ngx_mrb_raise_file_conf_error(mrb_state *mrb, mrb_value obj, ngx_conf_t *cf, char *code_file)
{  
    struct RString *str;
    char *err_out;
    
    obj = mrb_funcall(mrb, obj, "inspect", 0);
    if (mrb_type(obj) == MRB_TT_STRING) {
        str = mrb_str_ptr(obj);
        err_out = str->ptr;
        ngx_conf_log_error(NGX_LOG_ERR
            , cf
            , 0
            , "mrb_run failed. file: %s error: %s"
            , code_file
            , err_out
        );
    }
}

static mrb_value ngx_mrb_send_header(mrb_state *mrb, mrb_value self)
{
    ngx_mrb_rputs_chain_list_t *chain;
    ngx_http_mruby_ctx_t *ctx;

    ngx_http_request_t *r = ngx_mrb_get_request();
    mrb_int status = NGX_HTTP_OK;
    mrb_get_args(mrb, "i", &status);
    r->headers_out.status = status;

    ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR
            , r->connection->log
            , 0
            , "get mruby context failed."
        );
    }
    chain = ctx->rputs_chain;
    (*chain->last)->buf->last_buf = 1;

    if (r->headers_out.status == NGX_HTTP_OK) {
        ngx_http_send_header(r);
        ngx_http_output_filter(r, chain->out);
        ngx_http_set_ctx(r, NULL, ngx_http_mruby_module);
    }

    return self;
}


static mrb_value ngx_mrb_rputs(mrb_state *mrb, mrb_value self)
{
    mrb_value argv;
    ngx_buf_t *b;
    ngx_mrb_rputs_chain_list_t *chain;
    u_char *str;
    ngx_str_t ns;

    ngx_http_request_t *r = ngx_mrb_get_request();
    ngx_http_mruby_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);

    mrb_get_args(mrb, "o", &argv);

    if (mrb_type(argv) != MRB_TT_STRING) {
        argv = mrb_funcall(mrb, argv, "to_s", 0, NULL);
    }

    ns.data     = (u_char *)RSTRING_PTR(argv);
    ns.len      = ngx_strlen(ns.data);
    if (ns.len == 0) {
        return self;
    }

    if (ctx->rputs_chain == NULL) {
        chain       = ngx_pcalloc(r->pool, sizeof(ngx_mrb_rputs_chain_list_t));
        chain->out  = ngx_alloc_chain_link(r->pool);
        chain->last = &chain->out;
    } else {
        chain = ctx->rputs_chain;
        (*chain->last)->next = ngx_alloc_chain_link(r->pool);
        chain->last = &(*chain->last)->next;
    }
    b = ngx_calloc_buf(r->pool);
    (*chain->last)->buf = b;
    (*chain->last)->next = NULL;

    str         = ngx_pstrdup(r->pool, &ns);
    str[ns.len] = '\0';
    (*chain->last)->buf->pos    = str;
    (*chain->last)->buf->last   = str + ns.len;
    (*chain->last)->buf->memory = 1;
    ctx->rputs_chain = chain;
    ngx_http_set_ctx(r, ctx, ngx_http_mruby_module);

    if (r->headers_out.content_length_n == -1) {
        r->headers_out.content_length_n += ns.len + 1;
    } else {
        r->headers_out.content_length_n += ns.len;
    }

    return self;
}

static mrb_value ngx_mrb_errlogger(mrb_state *mrb, mrb_value self)
{   
    mrb_value *argv;
    mrb_value msg;
    mrb_int argc;
    mrb_int log_level;
    ngx_http_request_t *r = ngx_mrb_get_request();

    mrb_get_args(mrb, "*", &argv, &argc);
    if (argc != 2) {
        ngx_log_error(NGX_LOG_ERR
            , r->connection->log
            , 0
            , "%s ERROR %s: argument is not 2"
            , MODULE_NAME
            , __func__
        );
        return self;
    }
    if (mrb_type(argv[0]) != MRB_TT_FIXNUM) {
        ngx_log_error(NGX_LOG_ERR
            , r->connection->log
            , 0
            , "%s ERROR %s: argv[0] is not integer"
            , MODULE_NAME
            , __func__
        );
        return self;
    }
    log_level = mrb_fixnum(argv[0]);
    if (log_level < 0) {
        ngx_log_error(NGX_LOG_ERR
            , r->connection->log
            , 0
            , "%s ERROR %s: log level is not positive number"
            , MODULE_NAME
            , __func__
        );
        return self;
    }
    if (mrb_type(argv[1]) != MRB_TT_STRING) {
        msg = mrb_funcall(mrb, argv[1], "to_s", 0, NULL);
    } else {
        msg = mrb_str_dup(mrb, argv[1]);
    }
    ngx_log_error((ngx_uint_t)log_level, r->connection->log, 0, "%s", RSTRING_PTR(msg));

    return self;
}

static mrb_value ngx_mrb_get_ngx_mruby_version(mrb_state *mrb, mrb_value self)
{   
    return mrb_str_new_cstr(mrb, MODULE_VERSION);
}

static mrb_value ngx_mrb_get_nginx_version(mrb_state *mrb, mrb_value self)
{
    return mrb_str_new_cstr(mrb, NGINX_VERSION);
}

static mrb_value ngx_mrb_server_name(mrb_state *mrb, mrb_value self)
{
    return mrb_str_new_cstr(mrb, NGINX_VAR);
}

// like Nginx rewrite keywords
// used like this:
// => http code 3xx location in browser
// => internal redirection in nginx
static mrb_value ngx_mrb_redirect(mrb_state *mrb, mrb_value self)
{
    int                     argc;
    u_char                  *str;
    ngx_buf_t               *b;
    ngx_int_t               rc;
    mrb_value               uri, code;
    ngx_str_t               ns;
    ngx_http_mruby_ctx_t         *ctx;
    ngx_table_elt_t         *location;
    ngx_mrb_rputs_chain_list_t      *chain;

    ngx_http_request_t *r = ngx_mrb_get_request();
    argc = mrb_get_args(mrb, "o|oo", &uri, &code);

    // get status code from args
    if (argc == 2) {
        rc = mrb_fixnum(code);
    } else {
        rc = NGX_HTTP_MOVED_TEMPORARILY;
    }

    // get redirect uri from args
    if (mrb_type(uri) != MRB_TT_STRING) {
        uri = mrb_funcall(mrb, uri, "to_s", 0, NULL);
    }

    // save location uri to ns
    ns.data     = (u_char *)RSTRING_PTR(uri);
    ns.len      = ngx_strlen(ns.data);
    if (ns.len == 0) {
        return mrb_nil_value();
    }

    // if uri start with scheme prefix
    // return 3xx for redirect
    // else generate a internal redirection and response to raw request
    // request.path is not changed
    if (ngx_strncmp(ns.data, "http://", sizeof("http://") - 1) == 0 
        || ngx_strncmp(ns.data, "https://", sizeof("https://") - 1) == 0 
        || ngx_strncmp(ns.data, "$scheme", sizeof("$scheme") - 1) == 0) {    
        ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR
                , r->connection->log
                , 0
                , "get mruby context failed."
            );
        }

        if (ctx->rputs_chain == NULL) {
            chain       = ngx_pcalloc(r->pool, sizeof(ngx_mrb_rputs_chain_list_t));
            chain->out  = ngx_alloc_chain_link(r->pool);
            chain->last = &chain->out;
        } else {
            chain = ctx->rputs_chain;
            (*chain->last)->next = ngx_alloc_chain_link(r->pool);
            chain->last = &(*chain->last)->next;
        }

        // allocate space for body
        b = ngx_calloc_buf(r->pool);
        (*chain->last)->buf = b;
        (*chain->last)->next = NULL;

        str         = ngx_pstrdup(r->pool, &ns);
        str[ns.len] = '\0';
        (*chain->last)->buf->pos    = str;
        (*chain->last)->buf->last   = str+ns.len;
        (*chain->last)->buf->memory = 1;
        ctx->rputs_chain = chain;
        ngx_http_set_ctx(r, ctx, ngx_http_mruby_module);

        if (r->headers_out.content_length_n == -1) {
            r->headers_out.content_length_n += ns.len + 1;
        } else {
            r->headers_out.content_length_n += ns.len;
        }

        // build redirect location
        location = ngx_list_push(&r->headers_out.headers);
        location->hash = 1;
        ngx_str_set(&location->key, "Location");
        location->value = ns;
        location->lowcase_key = ngx_pnalloc(r->pool, location->value.len);
        ngx_strlow(location->lowcase_key, location->value.data, location->value.len);

        // set location and response code for hreaders
        r->headers_out.location = location;
        r->headers_out.status = rc;

        ngx_http_send_header(r);
        ngx_http_output_filter(r, chain->out);
    } else {
        ngx_http_internal_redirect(r, &ns, &r->args);
    }

    return self;
}

void ngx_mrb_core_init(mrb_state *mrb, struct RClass *class)
{
    mrb_define_method(mrb, mrb->kernel_module, "server_name", ngx_mrb_server_name, ARGS_NONE());

    mrb_define_const(mrb, class, "NGX_OK",                              mrb_fixnum_value(NGX_OK));
    mrb_define_const(mrb, class, "NGX_ERROR",                           mrb_fixnum_value(NGX_ERROR));
    mrb_define_const(mrb, class, "NGX_AGAIN",                           mrb_fixnum_value(NGX_AGAIN));
    mrb_define_const(mrb, class, "NGX_BUSY",                            mrb_fixnum_value(NGX_BUSY));
    mrb_define_const(mrb, class, "NGX_DONE",                            mrb_fixnum_value(NGX_DONE));
    mrb_define_const(mrb, class, "NGX_DECLINED",                        mrb_fixnum_value(NGX_DECLINED));
    mrb_define_const(mrb, class, "NGX_ABORT",                           mrb_fixnum_value(NGX_ABORT));
    mrb_define_const(mrb, class, "NGX_HTTP_OK",                         mrb_fixnum_value(NGX_HTTP_OK));
    mrb_define_const(mrb, class, "NGX_HTTP_CREATED",                    mrb_fixnum_value(NGX_HTTP_CREATED));
    mrb_define_const(mrb, class, "NGX_HTTP_ACCEPTED",                   mrb_fixnum_value(NGX_HTTP_ACCEPTED));
    mrb_define_const(mrb, class, "NGX_HTTP_NO_CONTENT",                 mrb_fixnum_value(NGX_HTTP_NO_CONTENT));
    mrb_define_const(mrb, class, "NGX_HTTP_SPECIAL_RESPONSE",           mrb_fixnum_value(NGX_HTTP_SPECIAL_RESPONSE));
    mrb_define_const(mrb, class, "NGX_HTTP_MOVED_PERMANENTLY",          mrb_fixnum_value(NGX_HTTP_MOVED_PERMANENTLY));
    mrb_define_const(mrb, class, "NGX_HTTP_MOVED_TEMPORARILY",          mrb_fixnum_value(NGX_HTTP_MOVED_TEMPORARILY));
    mrb_define_const(mrb, class, "NGX_HTTP_SEE_OTHER",                  mrb_fixnum_value(NGX_HTTP_SEE_OTHER));
    mrb_define_const(mrb, class, "NGX_HTTP_NOT_MODIFIED",               mrb_fixnum_value(NGX_HTTP_NOT_MODIFIED));
    mrb_define_const(mrb, class, "NGX_HTTP_TEMPORARY_REDIRECT",         mrb_fixnum_value(NGX_HTTP_TEMPORARY_REDIRECT));
    mrb_define_const(mrb, class, "NGX_HTTP_BAD_REQUEST",                mrb_fixnum_value(NGX_HTTP_BAD_REQUEST));
    mrb_define_const(mrb, class, "NGX_HTTP_UNAUTHORIZED",               mrb_fixnum_value(NGX_HTTP_UNAUTHORIZED));
    mrb_define_const(mrb, class, "NGX_HTTP_FORBIDDEN",                  mrb_fixnum_value(NGX_HTTP_FORBIDDEN));
    mrb_define_const(mrb, class, "NGX_HTTP_NOT_FOUND",                  mrb_fixnum_value(NGX_HTTP_NOT_FOUND));
    mrb_define_const(mrb, class, "NGX_HTTP_NOT_ALLOWED",                mrb_fixnum_value(NGX_HTTP_NOT_ALLOWED));
    mrb_define_const(mrb, class, "NGX_HTTP_REQUEST_TIME_OUT",           mrb_fixnum_value(NGX_HTTP_REQUEST_TIME_OUT));
    mrb_define_const(mrb, class, "NGX_HTTP_CONFLICT",                   mrb_fixnum_value(NGX_HTTP_CONFLICT));
    mrb_define_const(mrb, class, "NGX_HTTP_LENGTH_REQUIRED",            mrb_fixnum_value(NGX_HTTP_LENGTH_REQUIRED));
    mrb_define_const(mrb, class, "NGX_HTTP_PRECONDITION_FAILED",        mrb_fixnum_value(NGX_HTTP_PRECONDITION_FAILED));
    mrb_define_const(mrb, class, "NGX_HTTP_REQUEST_ENTITY_TOO_LARGE",   mrb_fixnum_value(NGX_HTTP_REQUEST_ENTITY_TOO_LARGE));
    mrb_define_const(mrb, class, "NGX_HTTP_REQUEST_URI_TOO_LARGE",      mrb_fixnum_value(NGX_HTTP_REQUEST_URI_TOO_LARGE));
    mrb_define_const(mrb, class, "NGX_HTTP_UNSUPPORTED_MEDIA_TYPE",     mrb_fixnum_value(NGX_HTTP_UNSUPPORTED_MEDIA_TYPE));
    mrb_define_const(mrb, class, "NGX_HTTP_RANGE_NOT_SATISFIABLE",      mrb_fixnum_value(NGX_HTTP_RANGE_NOT_SATISFIABLE));
    mrb_define_const(mrb, class, "NGX_HTTP_CLOSE",                      mrb_fixnum_value(NGX_HTTP_CLOSE));
    mrb_define_const(mrb, class, "NGX_HTTP_NGINX_CODES",                mrb_fixnum_value(NGX_HTTP_NGINX_CODES));
    mrb_define_const(mrb, class, "NGX_HTTP_REQUEST_HEADER_TOO_LARGE",   mrb_fixnum_value(NGX_HTTP_REQUEST_HEADER_TOO_LARGE));
    mrb_define_const(mrb, class, "NGX_HTTPS_CERT_ERROR",                mrb_fixnum_value(NGX_HTTPS_CERT_ERROR));
    mrb_define_const(mrb, class, "NGX_HTTPS_NO_CERT",                   mrb_fixnum_value(NGX_HTTPS_NO_CERT));
    mrb_define_const(mrb, class, "NGX_HTTP_TO_HTTPS",                   mrb_fixnum_value(NGX_HTTP_TO_HTTPS));
    mrb_define_const(mrb, class, "NGX_HTTP_CLIENT_CLOSED_REQUEST",      mrb_fixnum_value(NGX_HTTP_CLIENT_CLOSED_REQUEST));
    mrb_define_const(mrb, class, "NGX_HTTP_INTERNAL_SERVER_ERROR",      mrb_fixnum_value(NGX_HTTP_INTERNAL_SERVER_ERROR));
    mrb_define_const(mrb, class, "NGX_HTTP_NOT_IMPLEMENTED",            mrb_fixnum_value(NGX_HTTP_NOT_IMPLEMENTED));
    mrb_define_const(mrb, class, "NGX_HTTP_BAD_GATEWAY",                mrb_fixnum_value(NGX_HTTP_BAD_GATEWAY));
    mrb_define_const(mrb, class, "NGX_HTTP_SERVICE_UNAVAILABLE",        mrb_fixnum_value(NGX_HTTP_SERVICE_UNAVAILABLE));
    mrb_define_const(mrb, class, "NGX_HTTP_GATEWAY_TIME_OUT",           mrb_fixnum_value(NGX_HTTP_GATEWAY_TIME_OUT));
    mrb_define_const(mrb, class, "NGX_HTTP_INSUFFICIENT_STORAGE",       mrb_fixnum_value(NGX_HTTP_INSUFFICIENT_STORAGE));
    // error log priority
    mrb_define_const(mrb, class, "NGX_LOG_STDERR",                      mrb_fixnum_value(NGX_LOG_STDERR));
    mrb_define_const(mrb, class, "NGX_LOG_EMERG",                       mrb_fixnum_value(NGX_LOG_EMERG));
    mrb_define_const(mrb, class, "NGX_LOG_ALERT",                       mrb_fixnum_value(NGX_LOG_ALERT));
    mrb_define_const(mrb, class, "NGX_LOG_CRIT",                        mrb_fixnum_value(NGX_LOG_CRIT));
    mrb_define_const(mrb, class, "NGX_LOG_ERR",                         mrb_fixnum_value(NGX_LOG_ERR));
    mrb_define_const(mrb, class, "NGX_LOG_WARN",                        mrb_fixnum_value(NGX_LOG_WARN));
    mrb_define_const(mrb, class, "NGX_LOG_NOTICE",                      mrb_fixnum_value(NGX_LOG_NOTICE));
    mrb_define_const(mrb, class, "NGX_LOG_INFO",                        mrb_fixnum_value(NGX_LOG_INFO));
    mrb_define_const(mrb, class, "NGX_LOG_DEBUG",                       mrb_fixnum_value(NGX_LOG_DEBUG));

    mrb_define_class_method(mrb, class, "rputs",                        ngx_mrb_rputs,                      ARGS_ANY());
    mrb_define_class_method(mrb, class, "send_header",                  ngx_mrb_send_header,                ARGS_ANY());
    mrb_define_class_method(mrb, class, "return",                       ngx_mrb_send_header,                ARGS_ANY());
    mrb_define_class_method(mrb, class, "errlogger",                    ngx_mrb_errlogger,                  ARGS_ANY());
    mrb_define_class_method(mrb, class, "ngx_mruby_version",            ngx_mrb_get_ngx_mruby_version,      ARGS_NONE());
    mrb_define_class_method(mrb, class, "nginx_version",                ngx_mrb_get_nginx_version,          ARGS_NONE());
    mrb_define_class_method(mrb, class, "redirect",                     ngx_mrb_redirect,                      ARGS_ANY());
}
