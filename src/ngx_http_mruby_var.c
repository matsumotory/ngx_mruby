/*
// ngx_http_mruby_var.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_var.c
*/

#include "ngx_http_mruby_var.h"

#include <mruby.h>
#include <mruby/string.h>

static mrb_value ngx_mrb_var_method_missing(mrb_state *mrb, mrb_value self);
static mrb_value ngx_mrb_var_get(mrb_state *mrb, mrb_value self, const char *c_name);

/*
 *  ngx_http_core_variables
 *
    { ngx_string("http_host"), NULL, ngx_http_variable_header,
    { ngx_string("http_user_agent"), NULL, ngx_http_variable_header,
    { ngx_string("http_referer"), NULL, ngx_http_variable_header,
    { ngx_string("http_via"), NULL, ngx_http_variable_header,
    { ngx_string("http_x_forwarded_for"), NULL, ngx_http_variable_headers,
    { ngx_string("http_cookie"), NULL, ngx_http_variable_cookies,
    { ngx_string("content_length"), NULL, ngx_http_variable_content_length,
    { ngx_string("content_type"), NULL, ngx_http_variable_header,
    { ngx_string("host"), NULL, ngx_http_variable_host, 0, 0, 0 },
    { ngx_string("binary_remote_addr"), NULL,
    { ngx_string("remote_addr"), NULL, ngx_http_variable_remote_addr, 0, 0, 0 },
    { ngx_string("remote_port"), NULL, ngx_http_variable_remote_port, 0, 0, 0 },
    { ngx_string("server_addr"), NULL, ngx_http_variable_server_addr, 0, 0, 0 },
    { ngx_string("server_port"), NULL, ngx_http_variable_server_port, 0, 0, 0 },
    { ngx_string("server_protocol"), NULL, ngx_http_variable_request,
    { ngx_string("scheme"), NULL, ngx_http_variable_scheme, 0, 0, 0 },
    { ngx_string("https"), NULL, ngx_http_variable_https, 0, 0, 0 },
    { ngx_string("request_uri"), NULL, ngx_http_variable_request,
    { ngx_string("uri"), NULL, ngx_http_variable_request,
    { ngx_string("document_uri"), NULL, ngx_http_variable_request,
    { ngx_string("request"), NULL, ngx_http_variable_request_line, 0, 0, 0 },
    { ngx_string("document_root"), NULL,
    { ngx_string("realpath_root"), NULL,
    { ngx_string("query_string"), NULL, ngx_http_variable_request,
    { ngx_string("args"),
    { ngx_string("is_args"), NULL, ngx_http_variable_is_args,
    { ngx_string("request_filename"), NULL,
    { ngx_string("server_name"), NULL, ngx_http_variable_server_name, 0, 0, 0 },
    { ngx_string("request_method"), NULL,
    { ngx_string("remote_user"), NULL, ngx_http_variable_remote_user, 0, 0, 0 },
    { ngx_string("bytes_sent"), NULL, ngx_http_variable_bytes_sent,
    { ngx_string("body_bytes_sent"), NULL, ngx_http_variable_body_bytes_sent,
    { ngx_string("pipe"), NULL, ngx_http_variable_pipe,
    { ngx_string("request_completion"), NULL,
    { ngx_string("request_body"), NULL,
    { ngx_string("request_body_file"), NULL,
    { ngx_string("request_length"), NULL, ngx_http_variable_request_length,
    { ngx_string("request_time"), NULL, ngx_http_variable_request_time,
    { ngx_string("status"), NULL,
    { ngx_string("sent_http_content_type"), NULL,
    { ngx_string("sent_http_content_length"), NULL,
    { ngx_string("sent_http_location"), NULL,
    { ngx_string("sent_http_last_modified"), NULL,
    { ngx_string("sent_http_connection"), NULL,
    { ngx_string("sent_http_keep_alive"), NULL,
    { ngx_string("sent_http_transfer_encoding"), NULL,
    { ngx_string("sent_http_cache_control"), NULL, ngx_http_variable_headers,
    { ngx_string("limit_rate"), ngx_http_variable_request_set_size,
    { ngx_string("connection"), NULL,
    { ngx_string("connection_requests"), NULL,
    { ngx_string("nginx_version"), NULL, ngx_http_variable_nginx_version,
    { ngx_string("hostname"), NULL, ngx_http_variable_hostname,
    { ngx_string("pid"), NULL, ngx_http_variable_pid,
    { ngx_string("msec"), NULL, ngx_http_variable_msec,
    { ngx_string("time_iso8601"), NULL, ngx_http_variable_time_iso8601,
    { ngx_string("time_local"), NULL, ngx_http_variable_time_local,
    { ngx_string("tcpinfo_rtt"), NULL, ngx_http_variable_tcpinfo,
    { ngx_string("tcpinfo_rttvar"), NULL, ngx_http_variable_tcpinfo,
    { ngx_string("tcpinfo_snd_cwnd"), NULL, ngx_http_variable_tcpinfo,
    { ngx_string("tcpinfo_rcv_space"), NULL, ngx_http_variable_tcpinfo,
*/

static mrb_value ngx_mrb_var_get(mrb_state *mrb, mrb_value self, const char *c_name)
{
    ngx_http_request_t *r;
    ngx_http_variable_value_t *var;
    ngx_str_t ngx_name;

    u_char *low;
    size_t len;
    ngx_uint_t key;

    // get ngx_http_request_t
    r = ngx_mrb_get_request();

    // ngx_str_set(&ngx_name, c_name);
    ngx_name.len  = strlen(c_name);
    ngx_name.data = (u_char *)c_name;
    len                     = ngx_name.len;
    // check alloced memory
    if (len) {
        low = ngx_pnalloc(r->pool, len);
        if (low == NULL) {
            return mrb_nil_value();
        }
    } else {
        return mrb_nil_value();
    }
    // get variable with c string from nginx
    key = ngx_hash_strlow(low, ngx_name.data, len);
    var = ngx_http_get_variable(r, &ngx_name, key);

    // return variable value wraped with mruby string
    if (!var->not_found)
        return mrb_str_new(mrb, (char *)var->data, var->len);
    else
        return mrb_nil_value();
}

static mrb_value ngx_mrb_var_method_missing(mrb_state *mrb, mrb_value self)
{
    mrb_value name, *a;
    int alen;
    mrb_value s_name;
    char *c_name;

    // get var symble from method_missing(sym, *args)
    mrb_get_args(mrb, "n*", &name, &a, &alen);

    // name is a symble obj
    // first init name with mrb_symbol
    // second get mrb_string with mrb_sym2str
    s_name = mrb_sym2str(mrb, mrb_symbol(name));
    c_name = mrb_str_to_cstr(mrb, s_name);

    return ngx_mrb_var_get(mrb, self, c_name);
}

void ngx_mrb_var_class_init(mrb_state *mrb, struct RClass *class)
{
    struct RClass *class_var;

    class_var = mrb_define_class_under(mrb, class, "Var", mrb->object_class);
    mrb_define_method(mrb, class_var, "method_missing", ngx_mrb_var_method_missing, ARGS_ANY());
}
