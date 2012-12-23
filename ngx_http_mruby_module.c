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

#include "ngx_http_mruby.h"

// set conf
static void *ngx_http_mruby_loc_conf(ngx_conf_t *cf);
static char *ngx_http_mruby_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

// set fook function
static ngx_int_t ngx_http_mruby_post_read_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_mruby_server_rewrite_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_mruby_rewrite_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_mruby_access_checker(ngx_http_request_t *r);
static ngx_int_t ngx_http_mruby_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_mruby_log_handler(ngx_http_request_t *r);

// set fook phase
static char *ngx_http_mruby_post_read_request_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_server_rewrite_request_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_rewrite_request_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_access_checker_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_handler_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mruby_log_handler_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

// set init function
static ngx_int_t ngx_http_mruby_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_mruby_handler_init(ngx_http_core_main_conf_t *cmcf);

typedef struct {

    char *post_read_request_code_file;
    char *server_rewrite_request_code_file;
    char *rewrite_request_code_file;
    char *access_checker_code_file;
    char *handler_code_file;
    char *log_handler_code_file;

} ngx_http_mruby_loc_conf_t;
 
static ngx_command_t ngx_http_mruby_commands[] = {
    { ngx_string("mruby_post_read_request"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_post_read_request_phase,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
 
    { ngx_string("mruby_server_rewrite_request"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_server_rewrite_request_phase,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
 
    { ngx_string("mruby_rewrite_request"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_rewrite_request_phase,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
 
    { ngx_string("mruby_access_checker"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_access_checker_phase,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
 
    { ngx_string("mruby_handler"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_handler_phase,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
 
    { ngx_string("mruby_log_handler"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_log_handler_phase,
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
    ngx_http_mruby_merge_loc_conf  /* merge location configuration */
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

extern ngx_http_request_t *ngx_mruby_request_state;
 
static void *ngx_http_mruby_loc_conf(ngx_conf_t *cf)
{
    ngx_http_mruby_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mruby_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->post_read_request_code_file      = NGX_CONF_UNSET_PTR;
    conf->server_rewrite_request_code_file = NGX_CONF_UNSET_PTR;
    conf->rewrite_request_code_file        = NGX_CONF_UNSET_PTR;
    conf->access_checker_code_file         = NGX_CONF_UNSET_PTR;
    conf->handler_code_file                = NGX_CONF_UNSET_PTR;
    conf->log_handler_code_file            = NGX_CONF_UNSET_PTR;

    return conf;
}

static char *ngx_http_mruby_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_mruby_loc_conf_t *prev = parent;
    ngx_http_mruby_loc_conf_t *conf = child;

    if (prev->post_read_request_code_file == NGX_CONF_UNSET_PTR) {
        prev->post_read_request_code_file = conf->post_read_request_code_file;
    }

    if (prev->server_rewrite_request_code_file == NGX_CONF_UNSET_PTR) {
        prev->server_rewrite_request_code_file = conf->server_rewrite_request_code_file;
    }

    if (prev->rewrite_request_code_file == NGX_CONF_UNSET_PTR) {
        prev->rewrite_request_code_file = conf->rewrite_request_code_file;
    }

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_mruby_post_read_request(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)))
        return NGX_DECLINED;

    if (clcf->post_read_request_code_file == NGX_CONF_UNSET_PTR)
        return NGX_DECLINED;

    return ngx_mrb_run(r, clcf->post_read_request_code_file);
}

static ngx_int_t ngx_http_mruby_server_rewrite_request(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)))
        return NGX_DECLINED;

    if (clcf->server_rewrite_request_code_file == NGX_CONF_UNSET_PTR)
        return NGX_DECLINED;

    return ngx_mrb_run(r, clcf->server_rewrite_request_code_file);
}

static ngx_int_t ngx_http_mruby_rewrite_request(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)))
        return NGX_DECLINED;

    if (clcf->rewrite_request_code_file == NGX_CONF_UNSET_PTR)
        return NGX_DECLINED;

    return ngx_mrb_run(r, clcf->rewrite_request_code_file);
}

static ngx_int_t ngx_http_mruby_access_checker(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)))
        return NGX_DECLINED;

    if (clcf->access_checker_code_file == NGX_CONF_UNSET_PTR)
        return NGX_DECLINED;

    return ngx_mrb_run(r, clcf->access_checker_code_file);
}

static ngx_int_t ngx_http_mruby_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)))
        return NGX_DECLINED;

    if (clcf->handler_code_file == NGX_CONF_UNSET_PTR)
        return NGX_DECLINED;

    return ngx_mrb_run(r, clcf->handler_code_file);
}

static ngx_int_t ngx_http_mruby_log_handler(ngx_http_request_t *r)
{
    ngx_http_mruby_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_mruby_module);

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)))
        return NGX_DECLINED;

    if (clcf->log_handler_code_file == NGX_CONF_UNSET_PTR)
        return NGX_DECLINED;

    return ngx_mrb_run(r, clcf->log_handler_code_file);
}

static char * ngx_http_mruby_post_read_request_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *flcf = conf;
 
    value = cf->args->elts;
    flcf->post_read_request_code_file = (char *)value[1].data;

    return NGX_CONF_OK;
}

static char * ngx_http_mruby_server_rewrite_request_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *flcf = conf;
 
    value = cf->args->elts;
    flcf->server_rewrite_request_code_file = (char *)value[1].data;

    return NGX_CONF_OK;
}

static char * ngx_http_mruby_rewrite_request_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *flcf = conf;
 
    value = cf->args->elts;
    flcf->rewrite_request_code_file = (char *)value[1].data;

    return NGX_CONF_OK;
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

static char * ngx_http_mruby_log_handler_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_http_mruby_loc_conf_t *flcf = conf;

    value = cf->args->elts;
    flcf->log_handler_code_file = (char *)value[1].data;

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_mruby_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;

    ngx_mruby_request_state = NULL;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    if (ngx_http_mruby_handler_init(cmcf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_mruby_handler_init(ngx_http_core_main_conf_t *cmcf)
{
    ngx_int_t i;
    ngx_http_handler_pt *h;
    ngx_http_phases phase;
    ngx_http_phases phases[] = {
        NGX_HTTP_POST_READ_PHASE,
        //NGX_HTTP_FIND_CONFIG_PHASE,
        NGX_HTTP_SERVER_REWRITE_PHASE,
        NGX_HTTP_REWRITE_PHASE,
        //NGX_HTTP_POST_REWRITE_PHASE,
        //NGX_HTTP_PREACCESS_PHASE,
        NGX_HTTP_ACCESS_PHASE,
        //NGX_HTTP_POST_ACCESS_PHASE,
        //NGX_HTTP_TRY_FILES_PHASE,
        NGX_HTTP_CONTENT_PHASE,
        NGX_HTTP_LOG_PHASE,
    };
    ngx_int_t phases_c;

    phases_c = sizeof(phases) / sizeof(ngx_http_phases);
    for (i=0;i<phases_c;i++) {
        phase = phases[i];
        h = ngx_array_push(&cmcf->phases[phase].handlers);
        if (h == NULL) {
            return NGX_ERROR;
        }
        switch (phase) {
        case NGX_HTTP_POST_READ_PHASE:
            *h = ngx_http_mruby_post_read_request;
            break;
        case NGX_HTTP_SERVER_REWRITE_PHASE:
            *h = ngx_http_mruby_server_rewrite_request;
            break;
        case NGX_HTTP_REWRITE_PHASE:
            *h = ngx_http_mruby_rewrite_request;
            break;
        case NGX_HTTP_ACCESS_PHASE:
            *h = ngx_http_mruby_access_checker;
            break;
        case NGX_HTTP_CONTENT_PHASE:
            *h = ngx_http_mruby_handler;
            break;
        case NGX_HTTP_LOG_PHASE:
            *h = ngx_http_mruby_log_handler;
            break;
        default:
            // not through
            break;
        }
    }

    return NGX_OK;
}
