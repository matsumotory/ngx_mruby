/*
// ngx_http_mruby_ssl.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_ssl.h"

#if (NGX_HTTP_SSL)

#include "ngx_http_mruby_module.h"

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
  mscf->client_cert_path.data = NULL;
  mscf->client_cert_path.len = 0;
  mscf->client_cert_data.data = NULL;
  mscf->client_cert_data.len = 0;

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
  mrb_value msg;
  mrb_int log_level;
  ngx_http_mruby_srv_conf_t *mscf = mrb->ud;
  ngx_connection_t *c = mscf->connection;

  if (c == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't use logger at this phase. only use at request phase");
  }

  mrb_get_args(mrb, "io", &log_level, &msg);
  if (log_level < 0) {
    ngx_log_error(NGX_LOG_ERR, c->log, 0, "%s ERROR %s: log level is not positive number", MODULE_NAME, __func__);
    return self;
  }
  msg = mrb_obj_as_string(mrb, msg);
  ngx_log_error((ngx_uint_t)log_level, c->log, 0, "%*s", RSTRING_LEN(msg), RSTRING_PTR(msg));

  return self;
}

static mrb_value ngx_mrb_ssl_get_servername(mrb_state *mrb, mrb_value self)
{
  ngx_http_mruby_srv_conf_t *mscf = mrb->ud;

  return mrb_str_new(mrb, (char *)mscf->servername->data, mscf->servername->len);
}

static in_port_t get_in_port(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET) {
    return (((struct sockaddr_in *)sa)->sin_port);
  }

  return (((struct sockaddr_in6 *)sa)->sin6_port);
}

static mrb_value ngx_mrb_ssl_local_port(mrb_state *mrb, mrb_value self)
{
  ngx_http_mruby_srv_conf_t *mscf = mrb->ud;

  return mrb_fixnum_value(ntohs(get_in_port(mscf->connection->local_sockaddr)));
}

static mrb_value ngx_mrb_ssl_tls_version(mrb_state *mrb, mrb_value self)
{
  ngx_http_mruby_srv_conf_t *mscf = mrb->ud;
  ngx_connection_t *c = mscf->connection;
  ngx_ssl_conn_t *ssl_conn;

  if (c == NULL || c->ssl == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "invalid connection.");
  }

  ssl_conn = c->ssl->connection;
  if (ssl_conn == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "invalid ssl connection.");
  }

  return mrb_str_new_cstr(mrb, SSL_get_version(ssl_conn));
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

static mrb_value ngx_mrb_ssl_local_port(mrb_state *mrb, mrb_value self)
{
  mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_mrb_ssl_local_port doesn't support");
}

static mrb_value ngx_mrb_ssl_tls_version(mrb_state *mrb, mrb_value self)
{
  mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_mrb_ssl_tls_version doesn't support");
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x1000205fL */

NGX_MRUBY_DEFINE_METHOD_NGX_SET_SSL_MEMBER(cert, cert_path);
NGX_MRUBY_DEFINE_METHOD_NGX_SET_SSL_MEMBER(cert_key, cert_key_path);
NGX_MRUBY_DEFINE_METHOD_NGX_SET_SSL_MEMBER(cert_data, cert_data);
NGX_MRUBY_DEFINE_METHOD_NGX_SET_SSL_MEMBER(cert_key_data, cert_key_data);
NGX_MRUBY_DEFINE_METHOD_NGX_SET_SSL_MEMBER(client_cert, client_cert_path);
NGX_MRUBY_DEFINE_METHOD_NGX_SET_SSL_MEMBER(client_cert_data, client_cert_data);

void ngx_mrb_ssl_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_ssl;

  class_ssl = mrb_define_class_under(mrb, class, "SSL", mrb->object_class);
  mrb_define_method(mrb, class_ssl, "initialize", ngx_mrb_ssl_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_ssl, "servername", ngx_mrb_ssl_get_servername, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_ssl, "local_port", ngx_mrb_ssl_local_port, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_ssl, "tls_version", ngx_mrb_ssl_tls_version, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_ssl, "certificate=", ngx_mrb_ssl_set_cert, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_ssl, "certificate_key=", ngx_mrb_ssl_set_cert_key, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_ssl, "certificate_data=", ngx_mrb_ssl_set_cert_data, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_ssl, "certificate_key_data=", ngx_mrb_ssl_set_cert_key_data, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_ssl, "client_certificate=", ngx_mrb_ssl_set_client_cert, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_ssl, "client_certificate_data=", ngx_mrb_ssl_set_client_cert_data, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, class_ssl, "errlogger", ngx_mrb_ssl_errlogger, MRB_ARGS_REQ(2));
  mrb_define_class_method(mrb, class_ssl, "log", ngx_mrb_ssl_errlogger, MRB_ARGS_REQ(2));
}

#endif /* NGX_HTTP_SSL */
