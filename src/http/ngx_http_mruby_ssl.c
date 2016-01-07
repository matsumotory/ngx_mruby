/*
// ngx_http_mruby_ssl.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_module.h"
#include "ngx_http_mruby_ssl.h"

#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/compile.h>
#include <mruby/string.h>
#include <mruby/class.h>

static mrb_value ngx_mrb_ssl_set_cert(mrb_state *mrb, mrb_value self)
{
  ngx_http_mruby_srv_conf_t *mscf = mrb->ud;
  char *path;
  size_t path_len;

  mrb_get_args(mrb, "s", &path, &path_len);
  mscf->cert_path.data = (u_char *)path;
  mscf->cert_path.len = path_len;

  return mrb_str_new(mrb, (char *)mscf->cert_path.data, mscf->cert_path.len);
}

static mrb_value ngx_mrb_ssl_set_cert_key(mrb_state *mrb, mrb_value self)
{
  ngx_http_mruby_srv_conf_t *mscf = mrb->ud;
  char *path;
  size_t path_len;

  mrb_get_args(mrb, "s", &path, &path_len);
  mscf->cert_key_path.data = (u_char *)path;
  mscf->cert_key_path.len = path_len;

  return mrb_str_new(mrb, (char *)mscf->cert_key_path.data, mscf->cert_key_path.len);
}

void ngx_mrb_ssl_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_ssl;

  class_ssl = mrb_define_class_under(mrb, class, "SSL", mrb->object_class);
  mrb_define_method(mrb, class_ssl, "certificate=", ngx_mrb_ssl_set_cert, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_ssl, "certificate_key=", ngx_mrb_ssl_set_cert_key, MRB_ARGS_REQ(1));
}
