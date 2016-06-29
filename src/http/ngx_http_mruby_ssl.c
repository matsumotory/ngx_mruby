/*
// ngx_http_mruby_ssl.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_module.h"

#if (NGX_HTTP_SSL)

#include "ngx_http_mruby_ssl.h"

#include <mruby.h>
#include <mruby/class.h>
#include <mruby/compile.h>
#include <mruby/data.h>
#include <mruby/proc.h>
#include <mruby/string.h>

static mrb_value ngx_mrb_ssl_get_servername(mrb_state *mrb, mrb_value self)
{
  ngx_http_mruby_srv_conf_t *mscf = mrb->ud;

  return mrb_str_new(mrb, (char *)mscf->servername->data, mscf->servername->len);
}

static mrb_value ngx_mrb_ssl_set_cert(mrb_state *mrb, mrb_value self)
{
  ngx_http_mruby_srv_conf_t *mscf = mrb->ud;
  mrb_value path;

  mrb_get_args(mrb, "o", &path);
  mscf->cert_path.data = (u_char *)mrb_str_to_cstr(mrb, path);
  mscf->cert_path.len = RSTRING_LEN(path);

  return mrb_str_new(mrb, (char *)mscf->cert_path.data, mscf->cert_path.len);
}

static mrb_value ngx_mrb_ssl_set_cert_key(mrb_state *mrb, mrb_value self)
{
  ngx_http_mruby_srv_conf_t *mscf = mrb->ud;
  mrb_value path;

  mrb_get_args(mrb, "o", &path);
  mscf->cert_key_path.data = (u_char *)mrb_str_to_cstr(mrb, path);
  mscf->cert_key_path.len = RSTRING_LEN(path);

  return mrb_str_new(mrb, (char *)mscf->cert_key_path.data, mscf->cert_key_path.len);
}

static mrb_value ngx_mrb_ssl_set_cert_data(mrb_state *mrb, mrb_value self)
{
  ngx_http_mruby_srv_conf_t *mscf = mrb->ud;
  mrb_value data;

  mrb_get_args(mrb, "o", &data);
  mscf->cert_data.data = (u_char *)mrb_str_to_cstr(mrb, data);
  mscf->cert_data.len = RSTRING_LEN(data);

  return mrb_str_new(mrb, (char *)mscf->cert_data.data, mscf->cert_data.len);
}

static mrb_value ngx_mrb_ssl_set_cert_key_data(mrb_state *mrb, mrb_value self)
{
  ngx_http_mruby_srv_conf_t *mscf = mrb->ud;
  mrb_value data;

  mrb_get_args(mrb, "o", &data);
  mscf->cert_key_data.data = (u_char *)mrb_str_to_cstr(mrb, data);
  mscf->cert_key_data.len = RSTRING_LEN(data);;

  return mrb_str_new(mrb, (char *)mscf->cert_key_data.data, mscf->cert_key_data.len);
}

void ngx_mrb_ssl_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_ssl;

  class_ssl = mrb_define_class_under(mrb, class, "SSL", mrb->object_class);
  mrb_define_method(mrb, class_ssl, "servername", ngx_mrb_ssl_get_servername, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_ssl, "certificate=", ngx_mrb_ssl_set_cert, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_ssl, "certificate_key=", ngx_mrb_ssl_set_cert_key, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_ssl, "certificate_data=", ngx_mrb_ssl_set_cert_data, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_ssl, "certificate_key_data=", ngx_mrb_ssl_set_cert_key_data, MRB_ARGS_REQ(1));
}

#endif /* NGX_HTTP_SSL */
