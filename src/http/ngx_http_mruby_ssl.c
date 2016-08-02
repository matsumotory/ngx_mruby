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

#if OPENSSL_VERSION_NUMBER >= 0x1000205fL
#define NGX_MRUBY_DEFINE_METHOD_NGX_SET_SSL_MEMBER(method_suffix, member)                                              \
  static mrb_value ngx_mrb_ssl_set_##method_suffix(mrb_state *mrb, mrb_value self)                                     \
  {                                                                                                                    \
    ngx_http_mruby_srv_conf_t *mscf = mrb->ud;                                                                         \
    ngx_connection_t *c = mscf->connection;                                                                            \
    char *value;                                                                                                       \
    mrb_int len;                                                                                                       \
    u_char *valuep;                                                                                                    \
                                                                                                                       \
    mrb_get_args(mrb, "s", &value, &len);                                                                              \
    /* ngx_http_mruby_set_der_certificate() requires null terminated string. */                                        \
    valuep = ngx_palloc(c->pool, len + 1);                                                                             \
    if (valuep == NULL) {                                                                                              \
      ngx_log_error(NGX_LOG_ERR, c->log, 0, "%s ERROR %s:%d: memory allocate failed", MODULE_NAME,                     \
                        "ngx_mrb_ssl_set_" #method_suffix, __LINE__);                                                  \
      return mrb_nil_value();                                                                                          \
    }                                                                                                                  \
    ngx_cpystrn(valuep, (u_char *)value, len + 1);                                                                     \
    mscf->member.data = valuep;                                                                                        \
    mscf->member.len = len;                                                                                            \
                                                                                                                       \
    return mrb_str_new(mrb, (char *)mscf->member.data, mscf->member.len);                                              \
  }
#else /* ! OPENSSL_VERSION_NUMBER >= 0x1000205fL */
#define NGX_MRUBY_DEFINE_METHOD_NGX_SET_SSL_MEMBER(method_suffix, member)                                              \
  static mrb_value ngx_mrb_ssl_set_##method_suffix(mrb_state *mrb, mrb_value self)                                     \
  {                                                                                                                    \
    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_mrb_ssl_set_" #method_suffix "doesn't support");                              \
  }
#endif /* OPENSSL_VERSION_NUMBER >= 0x1000205fL */

static mrb_value ngx_mrb_ssl_get_servername(mrb_state *mrb, mrb_value self)
{
  ngx_http_mruby_srv_conf_t *mscf = mrb->ud;

  return mrb_str_new(mrb, (char *)mscf->servername->data, mscf->servername->len);
}

NGX_MRUBY_DEFINE_METHOD_NGX_SET_SSL_MEMBER(cert, cert_path);
NGX_MRUBY_DEFINE_METHOD_NGX_SET_SSL_MEMBER(cert_key, cert_key_path);
NGX_MRUBY_DEFINE_METHOD_NGX_SET_SSL_MEMBER(cert_data, cert_data);
NGX_MRUBY_DEFINE_METHOD_NGX_SET_SSL_MEMBER(cert_key_data, cert_key_data);

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
