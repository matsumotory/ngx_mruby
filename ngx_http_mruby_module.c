/*
// -------------------------------------------------------------------
// ngx_mruby
//      mruby module for nginx.
//
//      By matsumoto_r (MATSUMOTO, Ryosuke) Sep 2012 in Japan
//          Academic Center for Computing and Media Studies, Kyoto University
//          Graduate School of Informatics, Kyoto University
//          email: matsumoto_r at net.ist.i.kyoto-u.ac.jp
//
// Date     2012/07/28
//
// change log
//  2012/07/28 0.01 matsumoto_r first release
// -------------------------------------------------------------------
*/

#include <ngx_config.h>
#include <ngx_http.h>
#include <ngx_conf_file.h>
#include <nginx.h>

#include <sys/stat.h>
#include <stdio.h>
#include <string.h>

#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/compile.h>
#include <mruby/string.h>

// set conf
static void *ngx_http_mruby_loc_conf(ngx_conf_t *cf);

// set fook function
static ngx_int_t ngx_http_mruby_access_checker(ngx_http_request_t *r);
static ngx_int_t ngx_http_mruby_handler(ngx_http_request_t *r);

// set fook phase
static char *ngx_http_mruby_access_checker_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_handler_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

// set init function
static ngx_int_t ngx_http_mruby_init(ngx_conf_t *cf);

// define mruby method for nginx
mrb_value ngx_mrb_send_response(mrb_state *mrb, mrb_value self);
mrb_value ngx_mrb_rputs(mrb_state *mrb, mrb_value self);
mrb_value ngx_mrb_rputs2(mrb_state *mrb, mrb_value self);
mrb_value ngx_mrb_get_content_type(mrb_state *mrb, mrb_value self);
mrb_value ngx_mrb_set_content_type(mrb_state *mrb, mrb_value self);
mrb_value ngx_mrb_get_request_uri(mrb_state *mrb, mrb_value str);

typedef struct {

    char *handler_code_file;
    char *access_checker_code_file;

} ngx_http_mruby_loc_conf_t;
 
static ngx_command_t ngx_http_mruby_commands[] = {
    { ngx_string("mruby_handler"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_handler_phase,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
 
    { ngx_string("mruby_access_checker"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_access_checker_phase,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
 
    ngx_null_command
};
 
static ngx_http_module_t ngx_http_mruby_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_mruby_init,           /* postconfiguration */
 
    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */
 
    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */
 
    ngx_http_mruby_loc_conf,       /* create location configuration */
    NULL                           /* merge location configuration */
};
 
ngx_module_t ngx_http_mruby_module = {
    NGX_MODULE_V1,
    &ngx_http_mruby_module_ctx,    /* module context */
    ngx_http_mruby_commands,       /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_request_t *ngx_mruby_request_state = NULL;
 
static int ngx_mrb_push_request(ngx_http_request_t *r)
{
    ngx_mruby_request_state = r;
    return NGX_OK;
}

static ngx_http_request_t *ngx_mrb_get_request()
{
    return ngx_mruby_request_state;
}

static void *ngx_http_mruby_loc_conf(ngx_conf_t *cf)
{
    ngx_http_mruby_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mruby_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->handler_code_file         = NULL;
    conf->access_checker_code_file  = NULL;

    return conf;
}

mrb_value ngx_mrb_send_header(mrb_state *mrb, mrb_value self)
{
    ngx_http_request_t *r = ngx_mrb_get_request();

    mrb_int status = NGX_HTTP_OK;
    mrb_get_args(mrb, "i", &status);

    r->headers_out.status = status;
    ngx_http_send_header(r);

    return self;
}

mrb_value ngx_mrb_rputs(mrb_state *mrb, mrb_value self)
{
    mrb_value msg;
    ngx_buf_t *b;
    ngx_chain_t out;
    u_char *str;

    ngx_http_request_t *r = ngx_mrb_get_request();

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    out.buf = b;
    out.next = NULL;

    mrb_get_args(mrb, "o", &msg);

    if (mrb_type(msg) != MRB_TT_STRING)
        return self;

    str = (u_char *)RSTRING_PTR(msg);
    b->pos = str;
    b->last = str + strlen((char *)str);
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = strlen((char *)str);
    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *)"text/html";

    ngx_http_send_header(r);
    ngx_http_output_filter(r, &out);

    return self;
}

mrb_value ngx_mrb_rputs2(mrb_state *mrb, mrb_value self)
{
    mrb_value msg;
    ngx_buf_t *b;
    ngx_chain_t out;
    u_char *str;

    ngx_http_request_t *r = ngx_mrb_get_request();

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    out.buf = b;
    out.next = NULL;

    mrb_get_args(mrb, "o", &msg);

    if (mrb_type(msg) != MRB_TT_STRING)
        return self;

    str = (u_char *)RSTRING_PTR(msg);
    b->pos = str;
    b->last = str + strlen((char *)str);
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.content_length_n = strlen((char *)str);
    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *)"text/html";
    r->headers_out.status = NGX_HTTP_OK;

    ngx_http_send_header(r);
    ngx_http_output_filter(r, &out);

    return self;
}

mrb_value ngx_mrb_get_content_type(mrb_state *mrb, mrb_value self) 
{
    ngx_http_request_t *r = ngx_mrb_get_request();
    u_char *val = ngx_pstrdup(r->pool, &r->headers_out.content_type);
    return mrb_str_new(mrb, (char *)val, strlen((char *)val));
}

mrb_value ngx_mrb_set_content_type(mrb_state *mrb, mrb_value self) 
{
    mrb_value arg;
    u_char *str;

    ngx_http_request_t *r = ngx_mrb_get_request();
    mrb_get_args(mrb, "o", &arg);
    str = (u_char *)RSTRING_PTR(arg);

    //r->headers_out.content_type.len = sizeof((char *)str) - 1;
    ngx_str_set(&r->headers_out.content_type, str);
    //r->headers_out.content_type.data = str;

    return self;
}

mrb_value ngx_mrb_get_request_uri(mrb_state *mrb, mrb_value str)
{
    ngx_http_request_t *r = ngx_mrb_get_request();
    u_char *val = ngx_pstrdup(r->pool, &r->uri);
    return mrb_str_new(mrb, (char *)val, strlen((char *)val));
}

static int ngx_mrb_class_init(mrb_state *mrb)
{
    struct RClass *class;
    struct RClass *class_request;

    class = mrb_define_module(mrb, "Nginx");
    mrb_define_const(mrb, class, "NGX_OK", mrb_fixnum_value(NGX_OK));
    mrb_define_const(mrb, class, "NGX_ERROR", mrb_fixnum_value(NGX_ERROR));
    mrb_define_const(mrb, class, "NGX_AGAIN", mrb_fixnum_value(NGX_AGAIN));
    mrb_define_const(mrb, class, "NGX_BUSY", mrb_fixnum_value(NGX_BUSY));
    mrb_define_const(mrb, class, "NGX_DONE", mrb_fixnum_value(NGX_DONE));
    mrb_define_const(mrb, class, "NGX_DECLINED", mrb_fixnum_value(NGX_DECLINED));
    mrb_define_const(mrb, class, "NGX_ABORT", mrb_fixnum_value(NGX_ABORT));
    mrb_define_const(mrb, class, "NGX_HTTP_OK", mrb_fixnum_value(NGX_HTTP_OK));
    mrb_define_const(mrb, class, "NGX_HTTP_CREATED", mrb_fixnum_value(NGX_HTTP_CREATED));
    mrb_define_const(mrb, class, "NGX_HTTP_ACCEPTED", mrb_fixnum_value(NGX_HTTP_ACCEPTED));
    mrb_define_const(mrb, class, "NGX_HTTP_NO_CONTENT", mrb_fixnum_value(NGX_HTTP_NO_CONTENT));
    mrb_define_const(mrb, class, "NGX_HTTP_SPECIAL_RESPONSE", mrb_fixnum_value(NGX_HTTP_SPECIAL_RESPONSE));
    mrb_define_const(mrb, class, "NGX_HTTP_MOVED_PERMANENTLY", mrb_fixnum_value(NGX_HTTP_MOVED_PERMANENTLY));
    mrb_define_const(mrb, class, "NGX_HTTP_MOVED_TEMPORARILY", mrb_fixnum_value(NGX_HTTP_MOVED_TEMPORARILY));
    mrb_define_const(mrb, class, "NGX_HTTP_SEE_OTHER", mrb_fixnum_value(NGX_HTTP_SEE_OTHER));
    mrb_define_const(mrb, class, "NGX_HTTP_NOT_MODIFIED", mrb_fixnum_value(NGX_HTTP_NOT_MODIFIED));
    mrb_define_const(mrb, class, "NGX_HTTP_TEMPORARY_REDIRECT", mrb_fixnum_value(NGX_HTTP_TEMPORARY_REDIRECT));
    mrb_define_const(mrb, class, "NGX_HTTP_BAD_REQUEST", mrb_fixnum_value(NGX_HTTP_BAD_REQUEST));
    mrb_define_const(mrb, class, "NGX_HTTP_UNAUTHORIZED", mrb_fixnum_value(NGX_HTTP_UNAUTHORIZED));
    mrb_define_const(mrb, class, "NGX_HTTP_FORBIDDEN", mrb_fixnum_value(NGX_HTTP_FORBIDDEN));
    mrb_define_const(mrb, class, "NGX_HTTP_NOT_FOUND", mrb_fixnum_value(NGX_HTTP_NOT_FOUND));
    mrb_define_const(mrb, class, "NGX_HTTP_NOT_ALLOWED", mrb_fixnum_value(NGX_HTTP_NOT_ALLOWED));
    mrb_define_const(mrb, class, "NGX_HTTP_REQUEST_TIME_OUT", mrb_fixnum_value(NGX_HTTP_REQUEST_TIME_OUT));
    mrb_define_const(mrb, class, "NGX_HTTP_CONFLICT", mrb_fixnum_value(NGX_HTTP_CONFLICT));
    mrb_define_const(mrb, class, "NGX_HTTP_LENGTH_REQUIRED", mrb_fixnum_value(NGX_HTTP_LENGTH_REQUIRED));
    mrb_define_const(mrb, class, "NGX_HTTP_PRECONDITION_FAILED", mrb_fixnum_value(NGX_HTTP_PRECONDITION_FAILED));
    mrb_define_const(mrb, class, "NGX_HTTP_REQUEST_ENTITY_TOO_LARGE", mrb_fixnum_value(NGX_HTTP_REQUEST_ENTITY_TOO_LARGE));
    mrb_define_const(mrb, class, "NGX_HTTP_REQUEST_URI_TOO_LARGE", mrb_fixnum_value(NGX_HTTP_REQUEST_URI_TOO_LARGE));
    mrb_define_const(mrb, class, "NGX_HTTP_UNSUPPORTED_MEDIA_TYPE", mrb_fixnum_value(NGX_HTTP_UNSUPPORTED_MEDIA_TYPE));
    mrb_define_const(mrb, class, "NGX_HTTP_RANGE_NOT_SATISFIABLE", mrb_fixnum_value(NGX_HTTP_RANGE_NOT_SATISFIABLE));
    mrb_define_const(mrb, class, "NGX_HTTP_CLOSE", mrb_fixnum_value(NGX_HTTP_CLOSE));
    mrb_define_const(mrb, class, "NGX_HTTP_NGINX_CODES", mrb_fixnum_value(NGX_HTTP_NGINX_CODES));
    mrb_define_const(mrb, class, "NGX_HTTP_REQUEST_HEADER_TOO_LARGE", mrb_fixnum_value(NGX_HTTP_REQUEST_HEADER_TOO_LARGE));
    mrb_define_const(mrb, class, "NGX_HTTPS_CERT_ERROR", mrb_fixnum_value(NGX_HTTPS_CERT_ERROR));
    mrb_define_const(mrb, class, "NGX_HTTPS_NO_CERT", mrb_fixnum_value(NGX_HTTPS_NO_CERT));
    mrb_define_const(mrb, class, "NGX_HTTP_TO_HTTPS", mrb_fixnum_value(NGX_HTTP_TO_HTTPS));
    mrb_define_const(mrb, class, "NGX_HTTP_CLIENT_CLOSED_REQUEST", mrb_fixnum_value(NGX_HTTP_CLIENT_CLOSED_REQUEST));
    mrb_define_const(mrb, class, "NGX_HTTP_INTERNAL_SERVER_ERROR", mrb_fixnum_value(NGX_HTTP_INTERNAL_SERVER_ERROR));
    mrb_define_const(mrb, class, "NGX_HTTP_NOT_IMPLEMENTED", mrb_fixnum_value(NGX_HTTP_NOT_IMPLEMENTED));
    mrb_define_const(mrb, class, "NGX_HTTP_BAD_GATEWAY", mrb_fixnum_value(NGX_HTTP_BAD_GATEWAY));
    mrb_define_const(mrb, class, "NGX_HTTP_SERVICE_UNAVAILABLE", mrb_fixnum_value(NGX_HTTP_SERVICE_UNAVAILABLE));
    mrb_define_const(mrb, class, "NGX_HTTP_GATEWAY_TIME_OUT", mrb_fixnum_value(NGX_HTTP_GATEWAY_TIME_OUT));
    mrb_define_const(mrb, class, "NGX_HTTP_INSUFFICIENT_STORAGE", mrb_fixnum_value(NGX_HTTP_INSUFFICIENT_STORAGE));
    mrb_define_class_method(mrb, class, "rputs", ngx_mrb_rputs, ARGS_ANY());
    mrb_define_class_method(mrb, class, "send_header", ngx_mrb_send_header, ARGS_ANY());

    class_request = mrb_define_class_under(mrb, class, "Request", mrb->object_class);
    mrb_define_method(mrb, class_request, "content_type=", ngx_mrb_set_content_type, ARGS_ANY());
    mrb_define_method(mrb, class_request, "content_type", ngx_mrb_get_content_type, ARGS_NONE());
    mrb_define_method(mrb, class_request, "uri", ngx_mrb_get_request_uri, ARGS_NONE());

    return NGX_OK;
}

static int ngx_mrb_run(ngx_http_request_t *r, char *code_file)
{
    FILE *mrb_file;

    mrb_state *mrb = mrb_open();
    ngx_mrb_class_init(mrb);

    if ((mrb_file = fopen((char *)code_file, "r")) == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "mrb_file open failed");
    }

    struct mrb_parser_state* p = mrb_parse_file(mrb, mrb_file, NULL);
    int n = mrb_generate_code(mrb, p);
    mrb_pool_close(p->pool);
    ngx_mrb_push_request(r);
    mrb_run(mrb, mrb_proc_new(mrb, mrb->irep[n]), mrb_nil_value());

    return NGX_OK;
}
 
static ngx_int_t ngx_http_mruby_access_checker(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)))
        return NGX_DECLINED;

    if (clcf->access_checker_code_file == NULL)
        return NGX_DECLINED;

    return ngx_mrb_run(r, clcf->access_checker_code_file);
}

static ngx_int_t ngx_http_mruby_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)))
        return NGX_DECLINED;

    if (clcf->handler_code_file == NULL)
        return NGX_DECLINED;

    return ngx_mrb_run(r, clcf->handler_code_file);
}
 
static char * ngx_http_mruby_access_checker_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *flcf = conf;
 
    value = cf->args->elts;
    flcf->access_checker_code_file = (char *)value[1].data;

    return NGX_CONF_OK;
}

static char * ngx_http_mruby_handler_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *flcf = conf;
 
    value = cf->args->elts;
    flcf->handler_code_file = (char *)value[1].data;

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_mruby_init(ngx_conf_t *cf)
{   
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_mruby_access_checker;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_mruby_handler;

    return NGX_OK;
}
