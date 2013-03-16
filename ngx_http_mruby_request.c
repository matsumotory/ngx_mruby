/*
// ngx_http_mruby_request.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_request.h"

#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/compile.h>
#include <mruby/string.h>

ngx_http_request_t *ngx_mruby_request_state;

static mrb_value ngx_mrb_get_content_type(mrb_state *mrb, mrb_value self);
static mrb_value ngx_mrb_set_content_type(mrb_state *mrb, mrb_value self);
static mrb_value ngx_mrb_get_request_uri(mrb_state *mrb, mrb_value str);

ngx_int_t ngx_mrb_push_request(ngx_http_request_t *r)
{
    ngx_mruby_request_state = r;
    return NGX_OK;
}

ngx_http_request_t *ngx_mrb_get_request(void)
{
    return ngx_mruby_request_state;
}

static mrb_value ngx_mrb_get_content_type(mrb_state *mrb, mrb_value self) 
{
    ngx_http_request_t *r = ngx_mrb_get_request();
    return mrb_str_new_cstr(mrb, (char *)r->headers_out.content_type.data);
}

static mrb_value ngx_mrb_set_content_type(mrb_state *mrb, mrb_value self) 
{
    mrb_value arg;
    u_char *str;

    ngx_http_request_t *r = ngx_mrb_get_request();
    mrb_get_args(mrb, "o", &arg);
    
    if (mrb_nil_p(arg))
        return self;

    str = (u_char *)RSTRING_PTR(arg);
    //ngx_str_set(&r->headers_out.content_type, str);
    r->headers_out.content_type.len = ngx_strlen(str) + 1;
    r->headers_out.content_type.data = (u_char *)str;

    return self;
}

static mrb_value ngx_mrb_get_request_uri(mrb_state *mrb, mrb_value self)
{
    ngx_http_request_t *r = ngx_mrb_get_request();
    return mrb_str_new_cstr(mrb, (const char *)r->uri.data);
}

static mrb_value ngx_mrb_set_request_uri(mrb_state *mrb, mrb_value self)
{
    mrb_value arg;
    u_char *str;

    ngx_http_request_t *r = ngx_mrb_get_request();
    mrb_get_args(mrb, "o", &arg);
    str = (u_char *)RSTRING_PTR(arg);
    ngx_str_set(&r->uri, str);

    return self;
}

void ngx_mrb_request_class_init(mrb_state *mrb, struct RClass *class)
{
    struct RClass *class_request;

    class_request = mrb_define_class_under(mrb, class, "Request", mrb->object_class);
    mrb_define_method(mrb, class_request, "content_type=", ngx_mrb_set_content_type, ARGS_ANY());
    mrb_define_method(mrb, class_request, "content_type", ngx_mrb_get_content_type, ARGS_NONE());
    mrb_define_method(mrb, class_request, "uri", ngx_mrb_get_request_uri, ARGS_NONE());
    mrb_define_method(mrb, class_request, "uri=", ngx_mrb_set_request_uri, ARGS_ANY());
}
