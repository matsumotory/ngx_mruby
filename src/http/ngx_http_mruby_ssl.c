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

static mrb_value ngx_mrb_ssl_init(mrb_state *mrb, mrb_value self)
{
  ngx_http_mruby_srv_conf_t *mscf = mrb->ud;

  mscf->cert_path.data = NULL;
  mscf->cert_path.len = 0;
  mscf->cert_key_path.data = NULL;
  mscf->cert_key_path.len = 0;
  mscf->cert_data.data = NULL;
  mscf->cert_data.len = 0;
  mscf->cert_key_data.data = NULL;
  mscf->cert_key_data.len = 0;

  return self;
}

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
                    "ngx_mrb_ssl_set_" #method_suffix, __LINE__);                                                      \
      return mrb_nil_value();                                                                                          \
    }                                                                                                                  \
    ngx_cpystrn(valuep, (u_char *)value, len + 1);                                                                     \
    mscf->member.data = valuep;                                                                                        \
    mscf->member.len = len;                                                                                            \
                                                                                                                       \
    return mrb_str_new(mrb, (char *)mscf->member.data, mscf->member.len);                                              \
  }

static mrb_value ngx_mrb_ssl_errlogger(mrb_state *mrb, mrb_value self)
{
  mrb_value *argv;
  mrb_value msg;
  mrb_int argc;
  mrb_int log_level;
  ngx_http_mruby_srv_conf_t *mscf = mrb->ud;
  ngx_connection_t *c = mscf->connection;

  if (c == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't use logger at this phase. only use at request phase");
  }

  mrb_get_args(mrb, "*", &argv, &argc);
  if (argc != 2) {
    ngx_log_error(NGX_LOG_ERR, c->log, 0, "%s ERROR %s: argument is not 2", MODULE_NAME, __func__);
    return self;
  }
  if (mrb_type(argv[0]) != MRB_TT_FIXNUM) {
    ngx_log_error(NGX_LOG_ERR, c->log, 0, "%s ERROR %s: argv[0] is not integer", MODULE_NAME, __func__);
    return self;
  }
  log_level = mrb_fixnum(argv[0]);
  if (log_level < 0) {
    ngx_log_error(NGX_LOG_ERR, c->log, 0, "%s ERROR %s: log level is not positive number", MODULE_NAME, __func__);
    return self;
  }
  if (mrb_type(argv[1]) != MRB_TT_STRING) {
    msg = mrb_funcall(mrb, argv[1], "to_s", 0, NULL);
  } else {
    msg = mrb_str_dup(mrb, argv[1]);
  }
  ngx_log_error((ngx_uint_t)log_level, c->log, 0, "%s", mrb_str_to_cstr(mrb, msg));

  return self;
}

static mrb_value ngx_mrb_ssl_get_servername(mrb_state *mrb, mrb_value self)
{
  ngx_http_mruby_srv_conf_t *mscf = mrb->ud;

  return mrb_str_new(mrb, (char *)mscf->servername->data, mscf->servername->len);
}

#else /* ! OPENSSL_VERSION_NUMBER >= 0x1000205fL */

static mrb_value ngx_mrb_ssl_init(mrb_state *mrb, mrb_value self)
{
  mrb_raise(mrb, E_RUNTIME_ERROR, "Nginx::SSL doesn't support");
}

#define NGX_MRUBY_DEFINE_METHOD_NGX_SET_SSL_MEMBER(method_suffix, member)                                              \
  static mrb_value ngx_mrb_ssl_set_##method_suffix(mrb_state *mrb, mrb_value self)                                     \
  {                                                                                                                    \
    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_mrb_ssl_set_" #method_suffix "doesn't support");                              \
  }

static mrb_value ngx_mrb_ssl_errlogger(mrb_state *mrb, mrb_value self)
{
  mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_mrb_ssl_errlogger doesn't support");
}

static mrb_value ngx_mrb_ssl_get_servername(mrb_state *mrb, mrb_value self)
{
  mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_mrb_ssl_get_servername doesn't support");
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x1000205fL */

NGX_MRUBY_DEFINE_METHOD_NGX_SET_SSL_MEMBER(cert, cert_path);
NGX_MRUBY_DEFINE_METHOD_NGX_SET_SSL_MEMBER(cert_key, cert_key_path);
NGX_MRUBY_DEFINE_METHOD_NGX_SET_SSL_MEMBER(cert_data, cert_data);
NGX_MRUBY_DEFINE_METHOD_NGX_SET_SSL_MEMBER(cert_key_data, cert_key_data);

void ngx_mrb_ssl_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_ssl;

  class_ssl = mrb_define_class_under(mrb, class, "SSL", mrb->object_class);
  mrb_define_method(mrb, class_ssl, "initialize", ngx_mrb_ssl_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_ssl, "servername", ngx_mrb_ssl_get_servername, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_ssl, "certificate=", ngx_mrb_ssl_set_cert, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_ssl, "certificate_key=", ngx_mrb_ssl_set_cert_key, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_ssl, "certificate_data=", ngx_mrb_ssl_set_cert_data, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_ssl, "certificate_key_data=", ngx_mrb_ssl_set_cert_key_data, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, class_ssl, "errlogger", ngx_mrb_ssl_errlogger, MRB_ARGS_ANY());
  mrb_define_class_method(mrb, class_ssl, "log", ngx_mrb_ssl_errlogger, MRB_ARGS_ANY());
}

#endif /* NGX_HTTP_SSL */
