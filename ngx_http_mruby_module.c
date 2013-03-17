/*
** ngx_mruby - A Web Server Extension Mechanism Using mruby
**
** Copyright (c) ngx_mruby developers 2012-
**
** Permission is hereby granted, free of charge, to any person obtaining
** a copy of this software and associated documentation files (the
** "Software"), to deal in the Software without restriction, including
** without limitation the rights to use, copy, modify, merge, publish,
** distribute, sublicense, and/or sell copies of the Software, and to
** permit persons to whom the Software is furnished to do so, subject to
** the following conditions:
**
** The above copyright notice and this permission notice shall be
** included in all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
** EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
** MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
** IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
** CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
** TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
** SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
**
** [ MIT license: http://www.opensource.org/licenses/mit-license.php ]
*/
/*
** -------------------------------------------------------------------
** ngx_mruby
**      mruby module for nginx.
**
**      By matsumoto_r (MATSUMOTO, Ryosuke) Sep 2012 in Japan
**          Academic Center for Computing and Media Studies, Kyoto University
**          Graduate School of Informatics, Kyoto University
**          email: matsumoto_r at net.ist.i.kyoto-u.ac.jp
**
** Date     2012/07/28
**
** change log
**  2012/07/28 0.01 matsumoto_r first release
** -------------------------------------------------------------------
*/

#include <ngx_config.h>
#include <ngx_http.h>
#include <ngx_conf_file.h>
#include <nginx.h>

#include "ngx_http_mruby_module.h"
#include "ngx_http_mruby_request.h"
#include "ngx_http_mruby_handler.h"
#include "ngx_http_mruby_directive.h"

#define NGX_MRUBY_MERGE_STATE(prev_state, conf_state)   \
    if (prev_state == NGX_CONF_UNSET_PTR) {             \
        prev_state = conf_state;                        \
    }

// set conf
static void *ngx_http_mruby_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_mruby_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

// set init function
static ngx_int_t ngx_http_mruby_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_mruby_handler_init(ngx_http_core_main_conf_t *cmcf);

static ngx_command_t ngx_http_mruby_commands[] = {
    { ngx_string("mruby_cache"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mruby_loc_conf_t, cached),
      NULL },

    { ngx_string("mruby_post_read_handler"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_post_read_phase,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("mruby_server_rewrite_handler"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_server_rewrite_phase,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("mruby_rewrite_handler"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_rewrite_phase,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
 
    { ngx_string("mruby_access_handler"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_access_phase,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
 
    { ngx_string("mruby_content_handler"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_content_phase,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
 
    { ngx_string("mruby_log_handler"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_log_phase,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
 
    { ngx_string("mruby_post_read_handler_code"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_post_read_inline,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      ngx_http_mruby_post_read_inline_handler },

    { ngx_string("mruby_server_rewrite_handler_code"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_server_rewrite_inline,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      ngx_http_mruby_server_rewrite_inline_handler },

    { ngx_string("mruby_rewrite_handler_code"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_rewrite_inline,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      ngx_http_mruby_rewrite_inline_handler },

    { ngx_string("mruby_access_handler_code"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_access_inline,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      ngx_http_mruby_access_inline_handler },

    { ngx_string("mruby_content_handler_code"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_content_inline,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      ngx_http_mruby_content_inline_handler },
 
    { ngx_string("mruby_log_handler_code"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_mruby_log_inline,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      ngx_http_mruby_log_inline_handler },
 
    ngx_null_command
};
 
static ngx_http_module_t ngx_http_mruby_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_mruby_init,           /* postconfiguration */
 
    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */
 
    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */
 
    ngx_http_mruby_create_loc_conf,/* create location configuration */
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
 
static void *ngx_http_mruby_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_mruby_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mruby_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->post_read_state      = NGX_CONF_UNSET_PTR;
    conf->server_rewrite_state = NGX_CONF_UNSET_PTR;
    conf->rewrite_state        = NGX_CONF_UNSET_PTR;
    conf->access_state         = NGX_CONF_UNSET_PTR;
    conf->handler_state        = NGX_CONF_UNSET_PTR;
    conf->log_handler_state    = NGX_CONF_UNSET_PTR;

    conf->post_read_inline_state      = NGX_CONF_UNSET_PTR;
    conf->server_rewrite_inline_state = NGX_CONF_UNSET_PTR;
    conf->rewrite_inline_state        = NGX_CONF_UNSET_PTR;
    conf->access_inline_state         = NGX_CONF_UNSET_PTR;
    conf->content_inline_state        = NGX_CONF_UNSET_PTR;
    conf->log_inline_state            = NGX_CONF_UNSET_PTR;

    conf->cached = NGX_CONF_UNSET;

    return conf;
}

static char *ngx_http_mruby_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_mruby_loc_conf_t *prev = parent;
    ngx_http_mruby_loc_conf_t *conf = child;

    NGX_MRUBY_MERGE_STATE(prev->post_read_state,      conf->post_read_state);
    NGX_MRUBY_MERGE_STATE(prev->server_rewrite_state, conf->server_rewrite_state);
    NGX_MRUBY_MERGE_STATE(prev->rewrite_state,        conf->rewrite_state);
    NGX_MRUBY_MERGE_STATE(prev->access_state,         conf->access_state);
    NGX_MRUBY_MERGE_STATE(prev->handler_state,        conf->handler_state);
    NGX_MRUBY_MERGE_STATE(prev->log_handler_state,    conf->log_handler_state);

    NGX_MRUBY_MERGE_STATE(prev->post_read_inline_state,      conf->post_read_inline_state);
    NGX_MRUBY_MERGE_STATE(prev->server_rewrite_inline_state, conf->server_rewrite_inline_state);
    NGX_MRUBY_MERGE_STATE(prev->rewrite_inline_state,        conf->rewrite_inline_state);
    NGX_MRUBY_MERGE_STATE(prev->access_inline_state,         conf->access_inline_state);
    NGX_MRUBY_MERGE_STATE(prev->content_inline_state,        conf->content_inline_state);
    NGX_MRUBY_MERGE_STATE(prev->log_inline_state,            conf->log_inline_state);

    ngx_conf_merge_value(conf->cached, prev->cached, 0);

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
            *h = ngx_http_mruby_post_read_handler;
            h = ngx_array_push(&cmcf->phases[phase].handlers);
            if (h == NULL) {
                return NGX_ERROR;
            }
            *h = ngx_http_mruby_post_read_inline_handler;
            break;
        case NGX_HTTP_SERVER_REWRITE_PHASE:
            *h = ngx_http_mruby_server_rewrite_handler;
            h = ngx_array_push(&cmcf->phases[phase].handlers);
            if (h == NULL) {
                return NGX_ERROR;
            }
            *h = ngx_http_mruby_server_rewrite_inline_handler;
            break;
        case NGX_HTTP_REWRITE_PHASE:
            *h = ngx_http_mruby_rewrite_handler;
            h = ngx_array_push(&cmcf->phases[phase].handlers);
            if (h == NULL) {
                return NGX_ERROR;
            }
            *h = ngx_http_mruby_rewrite_inline_handler;
            break;
        case NGX_HTTP_ACCESS_PHASE:
            *h = ngx_http_mruby_access_handler;
            h = ngx_array_push(&cmcf->phases[phase].handlers);
            if (h == NULL) {
                return NGX_ERROR;
            }
            *h = ngx_http_mruby_access_inline_handler;
            break;
        case NGX_HTTP_CONTENT_PHASE:
            *h = ngx_http_mruby_content_handler;
            h = ngx_array_push(&cmcf->phases[phase].handlers);
            if (h == NULL) {
                return NGX_ERROR;
            }
            *h = ngx_http_mruby_content_inline_handler;
            break;
        case NGX_HTTP_LOG_PHASE:
            *h = ngx_http_mruby_log_handler;
            h = ngx_array_push(&cmcf->phases[phase].handlers);
            if (h == NULL) {
                return NGX_ERROR;
            }
            *h = ngx_http_mruby_log_inline_handler;
            break;
        default:
            // not through
            break;
        }
    }

    return NGX_OK;
}
