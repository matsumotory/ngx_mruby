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
// Date     2012/06/20
//
// change log
//  2012/06/20 0.00 matsumoto_r first release
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

static char *ngx_http_mruby(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct {

    ngx_str_t handler_code_file;

} ngx_http_mruby_loc_conf_t;
 
static ngx_command_t ngx_http_mruby_commands[] = {
    { ngx_string("mrubyHandler"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby,
      0,
      0,
      NULL },
 
    ngx_null_command
};
 
 
 
static ngx_http_module_t ngx_http_mruby_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */
 
    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */
 
    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */
 
    NULL,                          /* create location configuration */
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

static ngx_http_request_t ngx_mruby_request_state = NULL;
 
static int ap_mrb_push_request(ngx_http_request_t *r)
{
    ngx_mruby_request_state = r;
    return OK;
}

static ngx_http_request_t *ap_mrb_get_request()
{
    return ngx_mruby_request_state;
}

mrb_value ap_mrb_get_request_uri(mrb_state *mrb, mrb_value str)
{
    ngx_http_request_t = ap_mrb_get_request();
    u_char *val = ngx_pstrdup(r->pool, &r->uri);
    return mrb_str_new(mrb, val, strlen(val));
}

static int ap_ngx_mruby_class_init(mrb_state *mrb)
{
    struct RClass *class;
    struct RClass *class_manager;

    class = mrb_define_module(mrb, "Nginx");
    class_request = mrb_define_class_under(mrb, class, "Request", mrb->object_class);
    mrb_define_method(mrb, class_manager, "uri", ap_mrb_get_request_uri, ARGS_NONE());

    return OK;
}

static int ap_ngx_mruby_run(ngx_http_request_t *r, ngx_str_t *code_file)
{
    FILE *mrb_file;

    mrb_state *mrb = mrb_open();
    ap_mruby_class_init(mrb);

    if ((mrb_file = fopen(code_file->data, "r")) == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "mrb_file open failed.");
    }

    struct mrb_parser_state* p = mrb_parse_file(mrb, mrb_file);
    int n = mrb_generate_code(mrb, p->tree);
    mrb_pool_close(p->pool);
    ap_mrb_push_request(r);
    mrb_run(mrb, mrb_proc_new(mrb, mrb->irep[n]), mrb_nil_value());

    return NGX_OK;
}
 
static ngx_int_t ngx_http_mruby_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    return ap_ngx_mruby_run(r, clcf->handler_code_file);
}
 
 
static char * ngx_http_mruby(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_str_t *value, *url;
    ngx_http_core_loc_conf_t *clcf;

    ngx_http_mruby_loc_conf_t *flcf = conf;
 
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_mruby_handler;

    value = cf->args->elts;
    flcf->handler_cond_file = value[1];

    return NGX_CONF_OK;
}
