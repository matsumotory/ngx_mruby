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
#include "mruby/variable.h"

#include <nginx.h>
#include <ngx_http.h>
#include <ngx_conf_file.h>
#include <ngx_log.h>
#include <ngx_buf.h>

typedef struct rputs_chain_list {
    ngx_chain_t **last;
    ngx_chain_t *out;
} rputs_chain_list_t;

typedef struct ngx_mruby_ctx {
    rputs_chain_list_t *rputs_chain;
} ngx_mruby_ctx_t;

ngx_module_t  ngx_http_mruby_module;

static void ngx_mrb_raise_error(mrb_state *mrb, mrb_value obj, ngx_http_request_t *r);
static void ngx_mrb_raise_file_error(mrb_state *mrb, mrb_value obj, ngx_http_request_t *r, char *code_file);
static mrb_value ngx_mrb_send_header(mrb_state *mrb, mrb_value self);
static mrb_value ngx_mrb_rputs(mrb_state *mrb, mrb_value self);

static void rputs_chain_list_t_free(mrb_state *mrb, void *chain)
{
    ngx_http_request_t *r = ngx_mrb_get_request();
    ngx_free_chain(r->pool, ((rputs_chain_list_t *)chain)->out);
}

static const struct mrb_data_type rputs_chain_list_t_type = {
    "rputs_chain_list_t", rputs_chain_list_t_free,
};

ngx_int_t ngx_mrb_run(ngx_http_request_t *r, ngx_mrb_state_t *state)
{
    ngx_mruby_ctx_t *ctx;
    if (state == NGX_CONF_UNSET_PTR) {
        return NGX_DECLINED;
    }
    if ((ctx = ngx_pcalloc(r->pool, sizeof(*ctx))) == NULL) {
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
    mrb_run(state->mrb, mrb_proc_new(state->mrb, state->mrb->irep[state->n]), mrb_nil_value());
    if (state->mrb->exc) {
        if (state->file != NGX_CONF_UNSET_PTR) {
            ngx_mrb_raise_file_error(state->mrb, mrb_obj_value(state->mrb->exc), r, state->file);
        } else {
            ngx_mrb_raise_error(state->mrb, mrb_obj_value(state->mrb->exc), r);
        }
    }
    mrb_gc_arena_restore(state->mrb, state->ai);
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

static mrb_value ngx_mrb_send_header(mrb_state *mrb, mrb_value self)
{
    rputs_chain_list_t *chain;
    ngx_mruby_ctx_t *ctx;

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

    ngx_http_send_header(r);
    ngx_http_output_filter(r, chain->out);
    ngx_http_set_ctx(r, NULL, ngx_http_mruby_module);

    return self;
}


static mrb_value ngx_mrb_rputs(mrb_state *mrb, mrb_value self)
{
    mrb_value argv;
    ngx_buf_t *b;
    rputs_chain_list_t *chain;
    u_char *str;
    ngx_str_t ns;

    ngx_http_request_t *r = ngx_mrb_get_request();
    ngx_mruby_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);
    if (ctx->rputs_chain == NULL) {
        chain       = ngx_pcalloc(r->pool, sizeof(rputs_chain_list_t));
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

    mrb_get_args(mrb, "o", &argv);

    if (mrb_type(argv) != MRB_TT_STRING) {
        argv = mrb_funcall(mrb, argv, "to_s", 0, NULL);
    }

    ns.data     = (u_char *)RSTRING_PTR(argv);
    ns.len      = ngx_strlen(ns.data);
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
    return mrb_str_new2(mrb, MODULE_VERSION);
}

static mrb_value ngx_mrb_get_nginx_version(mrb_state *mrb, mrb_value self)
{
    return mrb_str_new2(mrb, NGINX_VERSION);
}

void ngx_mrb_core_init(mrb_state *mrb, struct RClass *class)
{
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
}
